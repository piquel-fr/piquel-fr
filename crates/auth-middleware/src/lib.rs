//! Resource-server validation configuration with no insecure construction path.

use piquel_auth_protocol::{Audience, UserId};
use thiserror::Error;
use url::Url;

/// A verified user identity, never a raw JWT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedUser {
    /// Immutable global account ID.
    pub user_id: UserId,
    /// Exact validated audience.
    pub audience: Audience,
}
/// Validation construction failure.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("issuer must be an absolute HTTPS URL")]
    /// The issuer or JWKS URL is not a trusted HTTPS URL.
    InvalidIssuer,
    #[error("an asymmetric algorithm must be selected")]
    /// The requested signing algorithm is not explicitly allowed.
    InvalidAlgorithm,
}
/// A production validator requires issuer, exact audience, trusted JWKS URL, and algorithm.
#[derive(Clone, Debug)]
pub struct AuthMiddleware {
    issuer: Url,
    audience: Audience,
    jwks_url: Url,
    algorithm: String,
}
impl AuthMiddleware {
    /// Returns the configured exact resource audience.
    #[must_use]
    pub fn expected_audience(&self) -> &Audience {
        &self.audience
    }

    /// Returns the trusted issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &Url {
        &self.issuer
    }

    /// Returns the trusted JWKS URL.
    #[must_use]
    pub fn jwks_url(&self) -> &Url {
        &self.jwks_url
    }

    /// Returns the explicitly allowed asymmetric algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Builds a validator without any signature, expiry, or audience bypass.
    ///
    /// # Errors
    /// Returns an error for non-HTTPS issuers/JWKS URLs or non-asymmetric algorithms.
    pub fn new(
        issuer: Url,
        audience: Audience,
        jwks_url: Url,
        algorithm: String,
    ) -> Result<Self, ConfigurationError> {
        if issuer.scheme() != "https" || jwks_url.scheme() != "https" {
            return Err(ConfigurationError::InvalidIssuer);
        }
        if !matches!(algorithm.as_str(), "ES256" | "RS256") {
            return Err(ConfigurationError::InvalidAlgorithm);
        }
        Ok(Self {
            issuer,
            audience,
            jwks_url,
            algorithm,
        })
    }
    /// Parses exactly one well-formed bearer credential before cryptographic validation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the header is malformed.
    pub fn bearer_header(value: &str) -> Result<&str, AuthenticationError> {
        let Some(token) = value.strip_prefix("Bearer ") else {
            return Err(AuthenticationError::MalformedBearer);
        };
        if token.is_empty() || token.contains(char::is_whitespace) {
            return Err(AuthenticationError::MalformedBearer);
        }
        Ok(token)
    }
}
/// A sanitized 401-class authentication failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("authentication failed")]
    /// The authorization header is malformed.
    MalformedBearer,
    #[error("authentication failed")]
    /// Cryptographic or claims validation failed.
    InvalidToken,
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    #[test]
    fn bearer_requires_one_value() {
        assert_eq!(
            AuthMiddleware::bearer_header("Bearer token").expect("one token"),
            "token"
        );
        assert!(AuthMiddleware::bearer_header("Bearer one two").is_err());
    }
    #[test]
    fn no_insecure_constructor() {
        assert!(
            AuthMiddleware::new(
                Url::parse("http://issuer").expect("url"),
                Audience::from_str("api").expect("audience"),
                Url::parse("https://issuer/jwks").expect("url"),
                "none".into()
            )
            .is_err()
        );
    }
}
