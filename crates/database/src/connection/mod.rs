//! Validated `PostgreSQL` transport, bounded pools and explicit maintenance.

use crate::{DatabaseConnectionError, DatabaseError, DatabaseTransaction};
use sqlx::{
    PgPool,
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

/// Maximum rows removed from each table in one maintenance batch.
const MAX_PURGE_BATCH: u32 = 1_000;
/// Cleanup deletes run by [`Database::purge_expired_auth_state`], in order, each
/// removing at most `$1` expired rows that no live request has locked.
const PURGE_STATEMENTS: [&str; 11] = [
    "DELETE FROM request_limits
    WHERE ctid IN (
        SELECT ctid
        FROM request_limits
        WHERE expires_at < now()
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM invitations
    WHERE ctid IN (
        SELECT ctid
        FROM invitations
        WHERE expires_at < now()
        OR redeemed_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM pending_federation
    WHERE ctid IN (
        SELECT ctid
        FROM pending_federation
        WHERE expires_at < now()
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM federation_transactions
    WHERE ctid IN (
        SELECT ctid
        FROM federation_transactions
        WHERE expires_at < now()
        OR consumed_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM webauthn_ceremonies
    WHERE ctid IN (
        SELECT ctid
        FROM webauthn_ceremonies
        WHERE expires_at < now()
        OR consumed_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM authorization_requests
    WHERE ctid IN (
        SELECT ctid
        FROM authorization_requests
        WHERE expires_at < now()
        OR consumed_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM authorization_codes
    WHERE ctid IN (
        SELECT ctid
        FROM authorization_codes
        WHERE expires_at < now()
        OR consumed_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM refresh_tokens t
    WHERE t.ctid IN (
        SELECT token.ctid
        FROM refresh_tokens token
        JOIN refresh_token_families family ON family.id = token.family_id
        WHERE token.expires_at < now()
        OR family.revoked_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE OF token SKIP LOCKED
    )",
    "DELETE FROM refresh_token_families f
    WHERE f.ctid IN (
        SELECT family.ctid
        FROM refresh_token_families family
        WHERE (
            family.revoked_at < now() - interval '1 day'
            OR family.created_at < now() - interval '31 days'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM refresh_tokens token
            WHERE token.family_id = family.id
        )
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
    "DELETE FROM browser_session_secrets b
    WHERE b.ctid IN (
        SELECT secret.ctid
        FROM browser_session_secrets secret
        JOIN sessions session ON session.id = secret.session_id
        WHERE session.expires_at < now()
        OR session.revoked_at < now() - interval '1 day'
        LIMIT $1
        FOR UPDATE OF secret SKIP LOCKED
    )",
    "DELETE FROM sessions s
    WHERE s.ctid IN (
        SELECT session.ctid
        FROM sessions session
        WHERE (
            session.expires_at < now()
            OR session.revoked_at < now() - interval '1 day'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM refresh_token_families family
            WHERE family.session_id = session.id
        )
        AND NOT EXISTS (
            SELECT 1
            FROM authorization_codes code
            WHERE code.session_id = session.id
        )
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    )",
];
/// Readiness must fail quickly when the database stops responding.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

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
            sqlx::query("SELECT 1").execute(&self.pool),
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

    /// Runs schema migrations when explicitly requested through the auth binary.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError::Operation`] if a migration fails or the applied
    /// history differs from the embedded migrations.
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|error| DatabaseError::Operation(Box::new(error)))
    }

    /// Purges a bounded batch of expired ephemeral authentication state and
    /// returns how many rows were deleted. `batch_size` is clamped to 1..=1000
    /// rows per table.
    ///
    /// Each table's batch commits on its own and skips rows that live requests have
    /// locked, so cleanup never holds locks across tables. Deleting a session can
    /// still wait briefly on a locked child row it cascades to.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a delete fails; earlier tables stay purged.
    pub async fn purge_expired_auth_state(&self, batch_size: u32) -> Result<u64, DatabaseError> {
        let limit = i64::from(batch_size.clamp(1, MAX_PURGE_BATCH));
        let mut deleted = 0;
        for statement in PURGE_STATEMENTS {
            deleted += sqlx::query(statement)
                .bind(limit)
                .execute(&self.pool)
                .await
                .map_err(DatabaseError::from)?
                .rows_affected();
        }
        Ok(deleted)
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
