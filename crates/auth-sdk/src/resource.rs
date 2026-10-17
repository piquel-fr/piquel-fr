//! Resource identifiers and access token validation.

use crate::{AccessToken, Issuer, ScopeSet, TokenError};
use chrono::{DateTime, Utc};
use piquel_auth_protocol::{claims::AccessTokenClaims, jwt::TokenType};
use serde::de::DeserializeOwned;
use std::{fmt, marker::PhantomData, str::FromStr};
use thiserror::Error;
use url::Url;

/// A resource identifier that is empty or holds spaces or control characters.
#[derive(Debug, Error)]
#[error("resource identifier must be non-empty printable ASCII without spaces")]
pub struct ResourceError;

/// A protected resource: the identifier its access tokens carry in `aud`. Auth
/// registers audiences such as `notes-api` today; RFC 8707 resource URIs such as
/// `https://notes.piquel.fr` work the same way. The identifier is kept exactly as
/// given, since `aud` is compared exactly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Resource {
    /// The resource identifier.
    identifier: String,
    /// Where the resource's protected resource metadata is served (RFC 9728).
    metadata: Option<Url>,
}

impl Resource {
    /// A resource with this identifier, such as `notes-api`.
    ///
    /// # Errors
    /// See [`ResourceError`].
    pub fn new(identifier: &str) -> Result<Self, ResourceError> {
        if identifier.is_empty() || !identifier.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ResourceError);
        }
        Ok(Self {
            identifier: identifier.to_owned(),
            metadata: None,
        })
    }

    /// Names where the resource serves its protected resource metadata (RFC 9728), so
    /// every challenge carries it as `resource_metadata` (§5.1).
    #[must_use]
    pub fn with_metadata(mut self, url: Url) -> Self {
        self.metadata = Some(url);
        self
    }

    /// The identifier, the `aud` its access tokens must contain.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Where the resource's protected resource metadata is served, if configured.
    #[must_use]
    pub const fn metadata(&self) -> Option<&Url> {
        self.metadata.as_ref()
    }
}

impl FromStr for Resource {
    type Err = ResourceError;
    /// Same as [`Resource::new`].
    fn from_str(identifier: &str) -> Result<Self, Self::Err> {
        Self::new(identifier)
    }
}

impl fmt::Display for Resource {
    /// Writes the identifier.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.identifier)
    }
}

/// Validates access tokens for one resource. `X` is the type of the application
/// claims, `()` by default; choose another with [`Self::with_claims`].
pub struct ResourceValidator<X = ()> {
    /// Issuer whose tokens are accepted.
    issuer: Issuer,
    /// The resource tokens must be for.
    resource: Resource,
    /// The application claims type.
    claims: PhantomData<fn() -> X>,
}

impl<X> Clone for ResourceValidator<X> {
    /// Shares the issuer.
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            resource: self.resource.clone(),
            claims: PhantomData,
        }
    }
}

impl<X> fmt::Debug for ResourceValidator<X> {
    /// Names the issuer and resource.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceValidator")
            .field("issuer", &self.issuer)
            .field("resource", &self.resource)
            .finish()
    }
}

impl ResourceValidator {
    /// Validates tokens of `issuer` for `resource`.
    pub(crate) const fn new(issuer: Issuer, resource: Resource) -> Self {
        Self {
            issuer,
            resource,
            claims: PhantomData,
        }
    }
}

impl<X> ResourceValidator<X> {
    /// The resource tokens must be for.
    #[must_use]
    pub const fn resource(&self) -> &Resource {
        &self.resource
    }

    /// The issuer whose tokens are accepted.
    #[must_use]
    pub const fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The current time by the issuer's clock, for
    /// [`AccessToken::require_authentication`].
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.issuer.now()
    }
}

impl<X: DeserializeOwned> ResourceValidator<X> {
    /// Reads application claims into `Y`, which must deserialize from the token's
    /// claims object.
    #[must_use]
    pub fn with_claims<Y: DeserializeOwned>(self) -> ResourceValidator<Y> {
        ResourceValidator {
            issuer: self.issuer,
            resource: self.resource,
            claims: PhantomData,
        }
    }

    /// Validates an access token and requires the scopes `S`. Use
    /// [`Scopes`](crate::Scopes) for `S` to require none and keep the granted list.
    ///
    /// # Errors
    /// See [`TokenError`]; checks run in the order of the SDK design.
    pub async fn validate<S: ScopeSet>(
        &self,
        token: &str,
    ) -> Result<AccessToken<S, X>, TokenError> {
        let claims: AccessTokenClaims<X> = self
            .issuer
            .decode(token, TokenType::Access, self.resource.identifier())
            .await?;
        AccessToken::from_claims(claims)?.into_scoped()
    }
}
