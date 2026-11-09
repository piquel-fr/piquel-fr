//! The database connections: the runtime role's, which every command uses, and
//! the schema owner's, which `migrate` and `audit prune` may use.

use super::AuthConfig;
use sourceorigin_common::config::{ConfigurationError, SecretReference, Variable};
use sourceorigin_repository::{DatabaseConfig, RuntimeRole};
use std::time::Duration;

/// Default number of pooled authentication connections.
const DATABASE_POOL_SIZE: u32 = 10;
/// Maximum startup wait for a pooled database connection.
const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

sourceorigin_common::variables! {
    /// The database's variables, in the configuration reference's order.
    #[cfg(test)]
    pub(crate) const VARIABLES;

    /// The PostgreSQL URL every command connects with. Over TCP it requires
    /// `sslmode=verify-full`, or an explicit `sslmode=disable` on a trusted
    /// private network. For a local Unix socket, use `localhost` as the host and
    /// the socket's absolute directory as the `host` parameter, such as
    /// `postgres://USER:PASSWORD@localhost/sourceorigin?host=/run/postgresql&sslmode=disable`.
    /// Required.
    const DATABASE_URL = "AUTH_DATABASE_URL";
    /// Where to read the database password, through `env://NAME` or
    /// `file:///path`, when the URL leaves it out.
    const DATABASE_PASSWORD = "AUTH_DATABASE_PASSWORD";
    /// The schema owner `migrate` connects as instead, in the same format as
    /// `AUTH_DATABASE_URL`, which `audit prune` uses too. `migrate` then creates
    /// or resets the role `AUTH_DATABASE_URL` names, with the
    /// `AUTH_DATABASE_PASSWORD` password and only row access to auth's tables. The
    /// owner must be a superuser.
    const DATABASE_OWNER_URL = "AUTH_DATABASE_OWNER_URL";
    /// Where to read the schema owner's password, as for `AUTH_DATABASE_PASSWORD`.
    const DATABASE_OWNER_PASSWORD = "AUTH_DATABASE_OWNER_PASSWORD";
}
/// The connection every command uses.
const RUNTIME_DATABASE: DatabaseVariables = DatabaseVariables {
    url: DATABASE_URL,
    password: DATABASE_PASSWORD,
};
/// The schema owner's connection, used only by `migrate`.
const OWNER_DATABASE: DatabaseVariables = DatabaseVariables {
    url: DATABASE_OWNER_URL,
    password: DATABASE_OWNER_PASSWORD,
};

/// A database connection's URL variable and its optional password variable.
#[derive(Clone, Copy)]
struct DatabaseVariables {
    /// `PostgreSQL` transport, database and user.
    url: Variable,
    /// Separately mounted password, for URLs without one.
    password: Variable,
}

impl DatabaseVariables {
    /// Reads the connection to `url`, the value of [`Self::url`], and returns it
    /// with its separately mounted password.
    fn read(self, url: &str) -> Result<(DatabaseConfig, Option<String>), ConfigurationError> {
        let config = DatabaseConfig::new(url, DATABASE_POOL_SIZE, DATABASE_CONNECT_TIMEOUT)
            .map_err(|source| {
                self.url.error(
                    "must be a postgres:// URL with sslmode=verify-full, explicit \
                     sslmode=disable, or a Unix socket",
                    source,
                )
            })?;
        let Some(reference) = self.password.optional()? else {
            return Ok((config, None));
        };
        let parsed = url::Url::parse(url)
            .map_err(|source| self.url.error("must be a postgres:// URL", source))?;
        if parsed.password().is_some() {
            return Err(self
                .password
                .invalid("must be omitted when the database URL contains a password"));
        }
        let secret = SecretReference::parse(&reference)
            .and_then(|reference| reference.resolve())
            .map_err(|source| {
                self.password
                    .error("must resolve through env://NAME or file://PATH", source)
            })?;
        let password = secret
            .utf8()
            .map_err(|source| self.password.error("must contain UTF-8 text", source))?
            .trim_end_matches('\n')
            .to_owned();
        Ok((config.with_password(&password), Some(password)))
    }
}

impl AuthConfig {
    /// Loads the runtime connection, which every command but an owner `migrate` uses.
    ///
    /// # Errors
    /// Names invalid transport settings or unresolved password references.
    pub fn database_from_environment() -> Result<DatabaseConfig, ConfigurationError> {
        Ok(RUNTIME_DATABASE.read(&DATABASE_URL.required()?)?.0)
    }

    /// Loads what `audit prune` connects with: the schema owner when
    /// `AUTH_DATABASE_OWNER_URL` is set, since the runtime role may not delete
    /// events, and the runtime connection otherwise.
    ///
    /// # Errors
    /// Names invalid transport settings or unresolved password references.
    pub fn owner_database_from_environment() -> Result<DatabaseConfig, ConfigurationError> {
        Ok(match DATABASE_OWNER_URL.optional()? {
            Some(url) => OWNER_DATABASE.read(&url)?.0,
            None => RUNTIME_DATABASE.read(&DATABASE_URL.required()?)?.0,
        })
    }

    /// Loads what `migrate` connects with: the schema owner when
    /// `AUTH_DATABASE_OWNER_URL` is set, along with the runtime role it then
    /// provisions, `AUTH_DATABASE_URL`'s user with `AUTH_DATABASE_PASSWORD`.
    /// Otherwise, the runtime connection alone.
    ///
    /// # Errors
    /// Names invalid transport settings, unresolved password references, or a
    /// runtime role that cannot be provisioned.
    pub fn migration_from_environment()
    -> Result<(DatabaseConfig, Option<RuntimeRole>), ConfigurationError> {
        let (runtime, password) = RUNTIME_DATABASE.read(&DATABASE_URL.required()?)?;
        let Some(url) = DATABASE_OWNER_URL.optional()? else {
            return Ok((runtime, None));
        };
        let (owner, _) = OWNER_DATABASE.read(&url)?;
        let password = password.ok_or(DATABASE_PASSWORD.invalid(
            "must be set with AUTH_DATABASE_OWNER_URL, for the runtime role, and \
             AUTH_DATABASE_URL must then omit its password",
        ))?;
        let role = RuntimeRole::new(&runtime, &password).map_err(|source| {
            DATABASE_URL.error("must name a role migrate can provision", source)
        })?;
        Ok((owner, Some(role)))
    }
}
