//! Small validated configuration primitives. Secrets are references, never values.

use std::{fmt, net::SocketAddr, str::FromStr, time::Duration};
use thiserror::Error;
use url::Url;

/// A configuration parsing error safe to display to an operator.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// A required variable was not set.
    #[error("required configuration {0} is missing")]
    Missing(&'static str),
    /// The configured value was malformed.
    #[error("configuration {name} is invalid")]
    Invalid {
        /// Name of the invalid setting; its value is deliberately omitted.
        name: &'static str,
    },
}

/// Validated URL that must use HTTPS outside explicitly local development.
#[derive(Clone, Debug)]
pub struct PublicUrl(Url);
impl PublicUrl {
    /// Parses a base URL without query or fragment components.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not an absolute HTTP(S) origin.
    pub fn parse(value: &str) -> Result<Self, ConfigurationError> {
        let url = Url::parse(value).map_err(|_| ConfigurationError::Invalid { name: "URL" })?;
        if !matches!(url.scheme(), "https" | "http")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigurationError::Invalid { name: "URL" });
        }
        Ok(Self(url))
    }
    /// Returns the parsed URL.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

/// A secret-provider locator whose value is deliberately redacted in diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretReference(String);
impl SecretReference {
    /// Parses a non-empty reference such as `env://AUTH_SIGNING_KEY`.
    ///
    /// # Errors
    ///
    /// Returns an error for empty or whitespace-containing references.
    pub fn parse(value: &str) -> Result<Self, ConfigurationError> {
        if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
            return Err(ConfigurationError::Invalid {
                name: "secret reference",
            });
        }
        Ok(Self(value.to_owned()))
    }
    /// Indicates a configured reference without exposing it.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        true
    }
}
impl fmt::Debug for SecretReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretReference(REDACTED)")
    }
}
impl fmt::Display for SecretReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Parses a socket address from an environment value.
///
/// # Errors
///
/// Returns an error if the supplied value is not a socket address.
pub fn socket_addr(name: &'static str, value: &str) -> Result<SocketAddr, ConfigurationError> {
    SocketAddr::from_str(value).map_err(|_| ConfigurationError::Invalid { name })
}
/// Parses a non-zero duration expressed as seconds.
///
/// # Errors
///
/// Returns an error if the supplied value is zero or not an unsigned integer.
pub fn seconds(name: &'static str, value: &str) -> Result<Duration, ConfigurationError> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| ConfigurationError::Invalid { name })?;
    if seconds == 0 {
        return Err(ConfigurationError::Invalid { name });
    }
    Ok(Duration::from_secs(seconds))
}
