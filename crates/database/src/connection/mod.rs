use crate::{DatabaseConnectionError, DatabaseError, DatabaseTransaction};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{str::FromStr, time::Duration};
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
    /// Creates production configuration using verified TLS, an explicit local Unix socket,
    /// or plaintext TCP explicitly requested with `sslmode=disable`.
    ///
    /// `max_connections` bounds the pool; `connect_timeout` bounds each wait
    /// for a pooled connection.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseConnectionError::InvalidConfiguration`] if the URL is
    /// not a `postgres` URL, either bound is zero, or the transport is insecure
    /// or ambiguous.
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

    /// Like [`Self::new`], but also allows unencrypted loopback databases
    /// without `sslmode`.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseConnectionError::InvalidConfiguration`] under the same
    /// conditions as [`Self::new`], except for plaintext loopback.
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

    /// Sets the password separately from the URL, e.g. from a mounted secret file.
    #[must_use]
    pub fn with_password(mut self, password: &str) -> Self {
        self.options = self.options.password(password);
        self
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
        let mut socket_paths = parsed
            .query_pairs()
            .filter_map(|(name, value)| (name == "host").then_some(value));
        let socket_path = socket_paths.next();
        if ssl_modes.next().is_some()
            || socket_paths.next().is_some()
            || socket_path.as_ref().is_some_and(|path| {
                host != "localhost" || !path.starts_with('/') || path.contains('\0')
            })
            || parsed.query_pairs().any(|(name, _)| name == "hostaddr")
        {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }
        let loopback = piquel_configuration::PublicUrl::has_loopback_host(&parsed);
        // Plaintext TCP needs an explicit `sslmode=disable`, e.g. on a private container
        // network. Weaker TLS modes would look encrypted without verifying the server.
        let plaintext = ssl_mode.as_deref() == Some("disable");
        let require_verified_tls =
            socket_path.is_none() && !plaintext && (!development || !loopback);
        if require_verified_tls && ssl_mode.as_deref() != Some("verify-full") {
            return Err(DatabaseConnectionError::InvalidConfiguration);
        }

        let options = PgConnectOptions::from_str(url)
            .map_err(|_| DatabaseConnectionError::InvalidConfiguration)?;
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
            Duration::from_secs(2),
            sqlx::query("SELECT 1").execute(&self.pool),
        )
        .await
        .map_err(|_| DatabaseError::Timeout)?
        .map(|_| ())
        .map_err(Into::into)
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
    /// # Errors
    ///
    /// Returns [`DatabaseError`] if a delete fails; nothing is purged then.
    pub async fn purge_expired_auth_state(&self, batch_size: u32) -> Result<u64, DatabaseError> {
        let limit = i64::from(batch_size.clamp(1, 1_000));
        let mut transaction = self.pool.begin().await.map_err(DatabaseError::from)?;
        let mut deleted = 0;
        for statement in [
            "DELETE FROM request_limits WHERE ctid IN (SELECT ctid FROM request_limits WHERE expires_at<now() LIMIT $1)",
            "DELETE FROM invitations WHERE ctid IN (SELECT ctid FROM invitations WHERE expires_at<now() OR redeemed_at<now()-interval '1 day' LIMIT $1)",
            "DELETE FROM pending_federation WHERE ctid IN (SELECT ctid FROM pending_federation WHERE expires_at<now() LIMIT $1)",
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
}

#[cfg(test)]
mod tests;
