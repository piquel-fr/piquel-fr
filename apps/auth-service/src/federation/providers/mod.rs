//! Shared provider code exchange and verified identity extraction. Each provider's
//! protocol facts and identity checks live in its own module.

use super::{FederationApplication, Provider};
use crate::email::NormalizedEmail;
use axum::http::{StatusCode, header};
use piquel_auth_protocol::oauth::GrantType;
use piquel_common::ConfigurationError;
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;

/// GitHub: OAuth profile and email fetching.
mod github;
/// Google: `OpenID` Connect ID-token verification.
mod google;
pub(super) use github::GitHubProtocol;
#[cfg(test)]
pub(super) use google::GoogleClaims;
pub(super) use google::GoogleProtocol;

/// Maximum stored byte length of a provider subject.
const MAX_SUBJECT_BYTES: usize = 255;
/// Maximum length of provider bearer credentials and ID tokens.
const MAX_TOKEN_BYTES: usize = 8192;
/// Maximum number of characters kept from a provider profile name.
const MAX_DISPLAY_NAME_CHARS: usize = 80;
/// Maximum provider response size, enforced while streaming chunked bodies too.
const MAX_RESPONSE_BYTES: usize = 65536;

/// Why a provider callback produced no verified identity. These failures are only
/// logged: the browser goes back to the login page with a generic error.
#[derive(Debug, Error)]
pub(super) enum ProviderError {
    /// The flow's provider was disabled since the flow started, e.g. by a restart.
    #[error("sign-in provider is not configured")]
    NotConfigured,
    /// The client secret is not UTF-8 text (startup checks this, so it should not happen).
    #[error(transparent)]
    Secret(#[from] ConfigurationError),
    /// A provider request could not be sent or its body could not be read.
    #[error("provider HTTP request failed")]
    Http(#[from] reqwest::Error),
    /// The provider answered with a non-success status, and its OAuth error if it sent one.
    #[error("provider answered HTTP {status}")]
    Status {
        /// Status of the provider's response.
        status: StatusCode,
        /// The provider's OAuth error body, when the response carried one.
        #[source]
        rejection: Option<ProviderRejection>,
    },
    /// A provider response is not the JSON we expect.
    #[error("provider returned unexpected JSON")]
    Json(#[from] serde_json::Error),
    /// A provider response is larger than we buffer.
    #[error("provider response exceeds {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    /// The verified subject is empty.
    #[error("provider subject is empty")]
    EmptySubject,
    /// The verified subject is longer than we store.
    #[error("provider subject is {0} bytes; at most {MAX_SUBJECT_BYTES} are stored")]
    SubjectTooLong(usize),
    /// GitHub's profile or token failed a GitHub-specific check.
    #[error(transparent)]
    GitHub(#[from] github::GitHubError),
    /// Google's ID token failed verification.
    #[error(transparent)]
    Google(#[from] google::GoogleError),
}

/// An OAuth error body (RFC 6749 section 5.2) returned by a provider.
#[derive(Debug, Deserialize, Error)]
#[error("{error}: {}", .error_description.as_deref().unwrap_or("no description"))]
pub(super) struct ProviderRejection {
    /// OAuth error code, such as `invalid_grant`.
    error: String,
    /// Human-readable explanation, when the provider sends one.
    error_description: Option<String>,
}

/// Every protocol fact about a provider. Back-channel URLs are `String`s so tests can
/// point them at a local fixture.
#[derive(Clone)]
pub(super) struct ProviderEndpoints {
    /// Issuer stored beside each subject, so subjects never collide across providers.
    pub(super) issuer: &'static str,
    /// Page the browser is sent to for authorization.
    pub(super) authorization: &'static str,
    /// Back-channel endpoint exchanging the authorization code.
    pub(super) token: String,
    /// Requested scopes, in the order sent to the provider.
    pub(super) scopes: &'static [&'static str],
    /// How the verified subject is read once the code is exchanged.
    pub(super) identity: IdentityStrategy,
}

impl ProviderEndpoints {
    /// Looks up a provider's facts, defined in its module. A new `Provider` fails to
    /// compile here until it has a module.
    pub(super) fn new(provider: Provider) -> Self {
        match provider {
            Provider::GitHub => Self::github(),
            Provider::Google => Self::google(),
        }
    }
}

/// How a provider proves who the user is after the shared code exchange.
#[derive(Clone)]
pub(super) enum IdentityStrategy {
    /// OAuth only: fetch the profile, then the verified primary email.
    GitHub(GitHubProtocol),
    /// `OpenID` Connect: identity comes only from a verified, nonce-bound ID token.
    Google(GoogleProtocol),
}

impl IdentityStrategy {
    /// Adds the provider's own parameters to its authorization URL.
    pub(super) fn extend_authorization(&self, url: &mut Url, nonce: &str) {
        match self {
            Self::GitHub(_) => {}
            Self::Google(_) => GoogleProtocol::extend_authorization(url, nonce),
        }
    }
}

/// Provider evidence that passed every check; usable for login or explicit linking.
pub(super) struct VerifiedIdentity {
    /// Stable provider account ID, independent of the email address.
    pub(super) subject: String,
    /// Normalized verified email, if the provider gave a valid one.
    pub(super) email: Option<String>,
    /// Profile name proposed for onboarding, at most `MAX_DISPLAY_NAME_CHARS` long.
    pub(super) display_name: String,
}

impl VerifiedIdentity {
    /// Rejects unstorable subjects, drops invalid emails and bounds the display name.
    fn new(
        subject: String,
        email: Option<String>,
        name: Option<String>,
        fallback_name: String,
    ) -> Result<Self, ProviderError> {
        if subject.is_empty() {
            return Err(ProviderError::EmptySubject);
        }
        if subject.len() > MAX_SUBJECT_BYTES {
            return Err(ProviderError::SubjectTooLong(subject.len()));
        }
        Ok(Self {
            subject,
            // An invalid optional email is dropped; email never proves account ownership.
            email: email.and_then(|email| {
                NormalizedEmail::parse(&email)
                    .inspect_err(|error| tracing::debug!(%error, "ignored provider email"))
                    .ok()
                    .map(|email| email.as_str().to_owned())
            }),
            display_name: name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(fallback_name)
                .chars()
                .take(MAX_DISPLAY_NAME_CHARS)
                .collect(),
        })
    }
}

impl FederationApplication {
    /// Exchanges a PKCE-bound code, then reads the identity the provider's way.
    pub(super) async fn exchange(
        &self,
        provider: Provider,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let config = self
            .providers
            .get(&provider)
            .ok_or(ProviderError::NotConfigured)?;
        let endpoints = &self.endpoints[&provider];
        let response = self
            .client
            .post(&endpoints.token)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("client_id", config.client_id.as_str()),
                ("client_secret", config.client_secret.utf8()?),
                ("code", code),
                ("redirect_uri", &self.callback_url(provider)),
                ("code_verifier", verifier),
                ("grant_type", GrantType::AuthorizationCode.as_str()),
            ])
            .send()
            .await?;
        match &endpoints.identity {
            IdentityStrategy::GitHub(protocol) => self.github_identity(response, protocol).await,
            IdentityStrategy::Google(protocol) => {
                self.google_identity(response, &config.client_id, nonce, protocol)
                    .await
            }
        }
    }

    /// Reads a success response as JSON. A failure status keeps the provider's OAuth
    /// error, if its body has one.
    async fn json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, ProviderError> {
        let status = response.status();
        let body = Self::body(response).await?;
        if !status.is_success() {
            return Err(ProviderError::Status {
                status,
                // Best effort: many failure bodies are not OAuth errors, and the status
                // alone still explains the failure.
                rejection: serde_json::from_slice(&body).ok(),
            });
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Buffers a response body, refusing bodies over `MAX_RESPONSE_BYTES`.
    async fn body(mut response: reqwest::Response) -> Result<Vec<u8>, ProviderError> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ProviderError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
