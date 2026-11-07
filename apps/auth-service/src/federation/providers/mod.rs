//! Shared provider code exchange and verified identity extraction. Each provider's
//! protocol facts and identity checks live in its own module; see
//! `docs/dev/extending/federation-providers.md` to add one.

use super::{FederationApplication, FederationConfigError, Provider};
use axum::http::{StatusCode, header};
use piquel_common::{
    config::ConfigurationError, email::NormalizedEmail, events::SignInFailure,
    protocol::oauth::GrantType,
};
use piquel_telemetry::SendTraced;
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

impl ProviderError {
    /// How a rejected provider sign-in is recorded, or `None` when the provider or
    /// this service failed rather than the evidence the browser brought back.
    pub(super) fn sign_in_failure(&self) -> Option<SignInFailure> {
        match self {
            Self::Status { status, .. } if status.is_client_error() => {
                Some(SignInFailure::InvalidCredential)
            }
            Self::EmptySubject | Self::SubjectTooLong(_) | Self::GitHub(_) | Self::Google(_) => {
                Some(SignInFailure::InvalidCredential)
            }
            Self::NotConfigured
            | Self::Secret(_)
            | Self::Http(_)
            | Self::Status { .. }
            | Self::Json(_)
            | Self::ResponseTooLarge => None,
        }
    }
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
    ///
    /// # Errors
    /// Fails if a built-in endpoint does not parse, or a key cache cannot be built.
    pub(super) fn new(provider: Provider) -> Result<Self, FederationConfigError> {
        match provider {
            Provider::GitHub => Ok(Self::github()),
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

/// The URL of a profile picture a provider reported: HTTPS, on that provider's
/// own picture host, so importing it fetches nothing else, and asking for the size
/// auth stores. Parsed when the provider reports it, and again when it is read
/// back from the pending evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProviderPicture(Url);

impl ProviderPicture {
    /// The longest URL kept, which the pending evidence's column also bounds.
    const MAX_LENGTH: usize = 2048;
    /// GitHub's host for avatars.
    const GITHUB_HOST: &str = "avatars.githubusercontent.com";
    /// The domain of Google's hosts for profile pictures, such as
    /// `lh3.googleusercontent.com`.
    const GOOGLE_DOMAIN: &str = ".googleusercontent.com";

    /// `url` as `provider`'s picture, or `None` when it is not one: not HTTPS, on
    /// another host or port, with credentials, or too long.
    pub(crate) fn parse(provider: Provider, url: &str) -> Option<Self> {
        if url.len() > Self::MAX_LENGTH {
            return None;
        }
        let mut url = Url::parse(url).ok()?;
        if url.scheme() != "https"
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return None;
        }
        let host = url.host_str()?.to_owned();
        let side = crate::pictures::SIDE.to_string();
        match provider {
            Provider::GitHub => {
                if host != Self::GITHUB_HOST {
                    return None;
                }
                // GitHub scales an avatar to its `s` parameter.
                let kept: Vec<(String, String)> = url
                    .query_pairs()
                    .filter(|(name, _)| name != "s")
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect();
                url.query_pairs_mut()
                    .clear()
                    .extend_pairs(kept)
                    .append_pair("s", &side);
            }
            Provider::Google => {
                if !host.ends_with(Self::GOOGLE_DOMAIN) {
                    return None;
                }
                // Google scales a picture to the `=s96-c` its path ends with.
                let resized = url.path().rsplit_once("=s").and_then(|(base, size)| {
                    let digits = size.split('-').next()?;
                    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
                        .then(|| format!("{base}=s{side}-c"))
                });
                if let Some(path) = resized {
                    url.set_path(&path);
                }
            }
        }
        // Asking for the size may have made it longer.
        (url.as_str().len() <= Self::MAX_LENGTH).then_some(Self(url))
    }

    /// The URL.
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// `url` taken as a provider's picture unchecked, so tests import from a
    /// local server.
    #[cfg(test)]
    pub(crate) fn local(url: &str) -> Self {
        Self(Url::parse(url).expect("picture URL"))
    }
}

/// Provider evidence that passed every check; usable for login or explicit linking.
pub(super) struct VerifiedIdentity {
    /// Stable provider account ID, independent of the email address.
    pub(super) subject: String,
    /// Normalized verified email, if the provider gave a valid one.
    pub(super) email: Option<String>,
    /// Whether the provider is authoritative for `email`, hosting its mailbox. A
    /// provider verified an address once, and the address may have changed owners
    /// since, as a lapsed domain does, unless the provider hosts it.
    pub(super) email_authoritative: bool,
    /// Profile name proposed for onboarding, at most `MAX_DISPLAY_NAME_CHARS` long.
    pub(super) display_name: String,
    /// The profile picture the provider reported, if it is one of its own.
    pub(super) picture: Option<ProviderPicture>,
}

impl VerifiedIdentity {
    /// Rejects unstorable subjects, drops invalid emails and pictures, and bounds
    /// the display name. The email comes with whether the provider hosts it.
    fn new(
        provider: Provider,
        subject: String,
        (email, authoritative): (Option<String>, bool),
        (name, fallback_name): (Option<String>, String),
        picture: Option<&str>,
    ) -> Result<Self, ProviderError> {
        if subject.is_empty() {
            return Err(ProviderError::EmptySubject);
        }
        if subject.len() > MAX_SUBJECT_BYTES {
            return Err(ProviderError::SubjectTooLong(subject.len()));
        }
        // An invalid optional email is dropped; email never proves account ownership.
        let email = email.and_then(|email| {
            NormalizedEmail::parse(&email)
                .inspect_err(|error| tracing::debug!(%error, "ignored provider email"))
                .ok()
                .map(|email| email.as_str().to_owned())
        });
        Ok(Self {
            subject,
            email_authoritative: authoritative && email.is_some(),
            email,
            display_name: name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(fallback_name)
                .chars()
                .take(MAX_DISPLAY_NAME_CHARS)
                .collect(),
            picture: picture.and_then(|picture| ProviderPicture::parse(provider, picture)),
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
            .send_traced()
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
