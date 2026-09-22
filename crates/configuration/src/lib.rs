//! Small validated configuration primitives. Secrets are references, never values.

use std::{env, fmt, fs};
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
    /// Returns an error when the value is not an absolute HTTPS URL without query or fragment.
    pub fn parse(value: &str) -> Result<Self, ConfigurationError> {
        let url = Url::parse(value).map_err(|_| ConfigurationError::Invalid { name: "URL" })?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigurationError::Invalid { name: "URL" });
        }
        Ok(Self(url))
    }

    /// Parses an explicit local-development HTTP(S) base URL.
    ///
    /// # Errors
    ///
    /// Returns an error unless the URL uses HTTP(S) and a loopback hostname.
    pub fn parse_development(value: &str) -> Result<Self, ConfigurationError> {
        let url = Url::parse(value).map_err(|_| ConfigurationError::Invalid { name: "URL" })?;
        if !Self::has_loopback_host(&url)
            || !matches!(url.scheme(), "http" | "https")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigurationError::Invalid { name: "URL" });
        }
        Ok(Self(url))
    }
    /// Tests a parsed URL host without reparsing bracketed IPv6 literals.
    #[must_use]
    pub fn has_loopback_host(url: &Url) -> bool {
        match url.host() {
            Some(url::Host::Domain(host)) => {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
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
        let allowed = ["env://", "file://"];
        if value.trim().is_empty()
            || value.chars().any(char::is_whitespace)
            || !allowed.iter().any(|prefix| value.starts_with(prefix))
            || allowed.contains(&value)
        {
            return Err(ConfigurationError::Invalid {
                name: "secret reference",
            });
        }
        Ok(Self(value.to_owned()))
    }
    /// Resolves environment and file references for local key providers.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider is unsupported or the secret is unavailable.
    pub fn resolve(&self) -> Result<SecretBytes, ConfigurationError> {
        let bytes = if let Some(name) = self.0.strip_prefix("env://") {
            env::var(name)
                .map(String::into_bytes)
                .map_err(|_| ConfigurationError::Invalid {
                    name: "secret reference",
                })?
        } else if let Some(path) = self.0.strip_prefix("file://") {
            fs::read(path).map_err(|_| ConfigurationError::Invalid {
                name: "secret reference",
            })?
        } else {
            return Err(ConfigurationError::Invalid {
                name: "unsupported key provider",
            });
        };
        if bytes.is_empty() {
            return Err(ConfigurationError::Invalid {
                name: "secret reference",
            });
        }
        Ok(SecretBytes(bytes))
    }
}

/// Resolved secret bytes whose diagnostic formatting is always redacted.
pub struct SecretBytes(Vec<u8>);
impl SecretBytes {
    /// Exposes bytes only to the security component that requested them.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_url_requires_https() {
        assert!(PublicUrl::parse("https://auth.piquel.fr").is_ok());
        assert!(PublicUrl::parse("http://auth.piquel.fr").is_err());
        assert!(PublicUrl::parse_development("http://localhost:3000").is_ok());
        assert!(PublicUrl::parse_development("http://example.com").is_err());
        assert!(PublicUrl::parse_development("http://[::1]:3000").is_ok());
        assert!(PublicUrl::parse_development("http://[2001:db8::1]").is_err());
    }

    #[test]
    fn secret_reference_is_allowlisted_and_redacted() {
        let reference = SecretReference::parse("env://AUTH_KEY").expect("valid reference");
        assert_eq!(format!("{reference:?}"), "SecretReference(REDACTED)");
        assert!(SecretReference::parse("https://example.com/key").is_err());
    }
}
