//! Environment variables, validated URLs and secret references, read once at startup.

use std::{env, error::Error as StdError, fmt, fs, path::PathBuf, str::FromStr};
use thiserror::Error;
use url::Url;

/// An operator-facing configuration error; supplied values are never displayed.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// A required variable is absent.
    #[error("{variable} is required")]
    Missing {
        /// Variable to set.
        variable: &'static str,
    },
    /// A value violates its contract, e.g. `AUTH_CLIENTS_FILE must contain unique client IDs`.
    #[error("{variable} {reason}")]
    Invalid {
        /// Variable to correct.
        variable: &'static str,
        /// What the value must look like, without the supplied value.
        reason: &'static str,
        /// The underlying parse or resolution failure, when there is one.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// Resolved secret bytes are not text.
    #[error("secret must contain UTF-8 text")]
    Utf8(#[from] std::str::Utf8Error),
}

/// A named environment variable, declared once beside its configuration section.
#[derive(Clone, Copy, Debug)]
pub struct Variable(&'static str);
impl Variable {
    /// Names an environment variable without reading it.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }
    /// Returns the name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.0
    }
    /// Rejects the value with `reason`, which says what the operator must change.
    #[must_use]
    pub const fn invalid(self, reason: &'static str) -> ConfigurationError {
        ConfigurationError::Invalid {
            variable: self.0,
            reason,
            source: None,
        }
    }
    /// Like [`Self::invalid`], keeping the underlying failure as the error's source.
    pub fn error(
        self,
        reason: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> ConfigurationError {
        ConfigurationError::Invalid {
            variable: self.0,
            reason,
            source: Some(Box::new(source)),
        }
    }
    /// Reads an optional UTF-8 setting.
    ///
    /// # Errors
    /// Returns an error for non-Unicode environment values, without exposing them.
    pub fn optional(self) -> Result<Option<String>, ConfigurationError> {
        match env::var(self.0) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            // VarError::NotUnicode contains the value, so it must not enter diagnostics.
            Err(env::VarError::NotUnicode(_)) => Err(self.invalid("must contain UTF-8 text")),
        }
    }
    /// Reads a required setting.
    ///
    /// # Errors
    /// Returns an error when absent or non-Unicode.
    pub fn required(self) -> Result<String, ConfigurationError> {
        self.optional()?
            .ok_or(ConfigurationError::Missing { variable: self.0 })
    }
    /// Reads an exact `true` or `false`, using `default` when absent.
    ///
    /// # Errors
    /// Returns an error for any other value.
    pub fn flag(self, default: bool) -> Result<bool, ConfigurationError> {
        match self.optional()?.as_deref() {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(_) => Err(self.invalid("must be true or false")),
        }
    }
    /// Parses a required setting into its validated type.
    ///
    /// # Errors
    /// Preserves the parsing failure and names the variable.
    pub fn parse<T: FromStr>(self) -> Result<T, ConfigurationError>
    where
        T::Err: StdError + Send + Sync + 'static,
    {
        self.required()?
            .parse()
            .map_err(|source| self.error("is invalid", source))
    }
    /// Parses an optional setting, falling back to `default` when it is absent.
    ///
    /// # Errors
    /// Preserves the parsing failure and names the variable.
    pub fn parse_or<T: FromStr>(self, default: &str) -> Result<T, ConfigurationError>
    where
        T::Err: StdError + Send + Sync + 'static,
    {
        self.optional()?
            .as_deref()
            .unwrap_or(default)
            .parse()
            .map_err(|source| self.error("is invalid", source))
    }
    /// Parses an optional setting; `None` when it is absent.
    ///
    /// # Errors
    /// Preserves the parsing failure and names the variable.
    pub fn parse_optional<T: FromStr>(self) -> Result<Option<T>, ConfigurationError>
    where
        T::Err: StdError + Send + Sync + 'static,
    {
        self.optional()?
            .map(|value| {
                value
                    .parse()
                    .map_err(|source| self.error("is invalid", source))
            })
            .transpose()
    }
}

/// Why a configured URL was rejected. Each message tells the operator what to change.
#[derive(Debug, Error)]
pub enum UrlError {
    /// The value is not an absolute URL.
    #[error("must be an absolute URL, e.g. https://piquel.fr/settings")]
    Malformed(#[source] url::ParseError),
    /// Only HTTPS is accepted; every environment is served over TLS.
    #[error("must use https://")]
    NotHttps,
    /// The URL has no host.
    #[error("must include a host name")]
    MissingHost,
    /// Credentials in a URL would leak into logs and redirects.
    #[error("must not contain a user name or password")]
    Credentials,
    /// Queries and fragments are not part of a base URL.
    #[error("must not contain a query or fragment")]
    QueryOrFragment,
    /// An origin cannot carry a path.
    #[error("must be an origin without a path, e.g. https://auth.piquel.fr")]
    Path,
}

/// An absolute HTTPS URL without credentials, query or fragment.
#[derive(Clone, Debug)]
pub struct PublicUrl(Url);
impl PublicUrl {
    /// Exposes the validated URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }
}
impl FromStr for PublicUrl {
    type Err = UrlError;
    /// Accepts an absolute HTTPS URL, optionally with a path.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(value).map_err(UrlError::Malformed)?;
        if url.scheme() != "https" {
            return Err(UrlError::NotHttps);
        }
        if url.host_str().is_none() {
            return Err(UrlError::MissingHost);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UrlError::Credentials);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(UrlError::QueryOrFragment);
        }
        Ok(Self(url))
    }
}

/// An HTTPS origin such as `https://auth.piquel.fr`, validated once at startup.
#[derive(Clone, Debug)]
pub struct Origin {
    /// The origin as a URL, always with the root path.
    url: Url,
    /// Host name, kept separately because parsing guarantees it exists.
    host: String,
}
impl Origin {
    /// Exposes the validated URL, whose path is always `/`.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.url
    }
    /// The origin's host name, e.g. `auth.piquel.fr`.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    /// The origin without its trailing slash, as used in `Origin` headers and OIDC issuers.
    #[must_use]
    pub fn serialized(&self) -> String {
        self.url.origin().ascii_serialization()
    }
    /// The absolute URL of `path`, which must start with `/`, on this origin.
    #[must_use]
    pub fn url(&self, path: &str) -> Url {
        let mut url = self.url.clone();
        url.set_path(path);
        url
    }
    /// Like [`Self::url`], as text.
    #[must_use]
    pub fn join(&self, path: &str) -> String {
        self.url(path).into()
    }
}
impl FromStr for Origin {
    type Err = UrlError;
    /// Accepts an HTTPS origin without path, credentials, query or fragment.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let PublicUrl(url) = value.parse()?;
        if url.path() != "/" {
            return Err(UrlError::Path);
        }
        let host = url.host_str().ok_or(UrlError::MissingHost)?.to_owned();
        Ok(Self { url, host })
    }
}

/// Why a secret reference could not be parsed or resolved. Messages never contain
/// the reference or the secret.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The reference is not `env://NAME` or `file://PATH`.
    #[error("secret reference is not env://NAME or file://PATH")]
    Malformed,
    /// The referenced environment variable is not set.
    #[error("secret environment variable is not set")]
    MissingVariable,
    /// The referenced environment variable is not UTF-8. The rejected value is the
    /// secret itself, so it is dropped instead of kept as a source.
    #[error("secret environment variable must contain UTF-8 text")]
    NotUnicode,
    /// The referenced file could not be read.
    #[error("could not read the secret file")]
    Unreadable(#[source] std::io::Error),
    /// The secret resolved to zero bytes.
    #[error("secret must not be empty")]
    Empty,
}

/// A validated `env://NAME` or `file://PATH` secret locator, redacted in diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretReference(SecretLocation);

/// Where a [`SecretReference`] points, kept private so every value is validated.
#[derive(Clone, PartialEq, Eq)]
enum SecretLocation {
    /// Name of the process variable holding the secret.
    Environment(String),
    /// Path of the mounted secret file.
    File(PathBuf),
}
impl SecretReference {
    /// Prefix of environment variable references.
    const ENVIRONMENT_PREFIX: &str = "env://";
    /// Prefix of mounted file references.
    const FILE_PREFIX: &str = "file://";

    /// Parses an `env://NAME` or `file://PATH` secret locator.
    ///
    /// # Errors
    /// Rejects unsupported, empty or whitespace-containing references.
    pub fn parse(value: &str) -> Result<Self, SecretError> {
        value.parse()
    }
    /// Reads the secret without ever logging it.
    ///
    /// # Errors
    /// Reports a missing, non-UTF-8, unreadable or empty secret.
    pub fn resolve(&self) -> Result<SecretBytes, SecretError> {
        let bytes = match &self.0 {
            // var_os keeps the value out of the error, unlike env::var.
            SecretLocation::Environment(name) => env::var_os(name)
                .ok_or(SecretError::MissingVariable)?
                .into_string()
                .map_err(|_| SecretError::NotUnicode)?
                .into_bytes(),
            SecretLocation::File(path) => fs::read(path).map_err(SecretError::Unreadable)?,
        };
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(SecretBytes(bytes))
    }
}
impl FromStr for SecretReference {
    type Err = SecretError;
    /// Accepts a known prefix followed by a nonempty locator without whitespace.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let valid = |locator: &str| !locator.is_empty() && !locator.contains(char::is_whitespace);
        let location = match (
            value.strip_prefix(Self::ENVIRONMENT_PREFIX),
            value.strip_prefix(Self::FILE_PREFIX),
        ) {
            (Some(name), _) if valid(name) => SecretLocation::Environment(name.to_owned()),
            (_, Some(path)) if valid(path) => SecretLocation::File(path.into()),
            _ => return Err(SecretError::Malformed),
        };
        Ok(Self(location))
    }
}

/// Resolved bytes with redacted diagnostic formatting.
pub struct SecretBytes(Vec<u8>);
impl SecretBytes {
    /// Exposes secret bytes to the component that requested them.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
    /// Borrows a text secret without copying it.
    ///
    /// # Errors
    /// Preserves invalid UTF-8 diagnostics without displaying secret bytes.
    pub fn utf8(&self) -> Result<&str, ConfigurationError> {
        Ok(std::str::from_utf8(&self.0)?)
    }
}
impl fmt::Debug for SecretBytes {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}
impl fmt::Debug for SecretReference {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretReference(REDACTED)")
    }
}
impl fmt::Display for SecretReference {
    /// Renders a safe diagnostic representation without exposing secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Focused tests for configuration validation and its redaction contracts.
#[cfg(test)]
mod tests;
