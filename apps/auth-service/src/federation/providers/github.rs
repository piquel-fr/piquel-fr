//! GitHub sign-in: plain OAuth, so the identity comes from GitHub's API, not a token.

use super::{
    FederationApplication, IdentityStrategy, MAX_TOKEN_BYTES, ProviderEndpoints, ProviderError,
    ProviderRejection, VerifiedIdentity,
};
use axum::http::StatusCode;
use piquel_telemetry::SendTraced;
use serde::Deserialize;
use thiserror::Error;

/// GitHub scopes: the public profile plus the account's email addresses.
const SCOPES: &[&str] = &["read:user", "user:email"];

/// GitHub responses that fail GitHub-specific checks.
#[derive(Debug, Error)]
pub(in crate::federation) enum GitHubError {
    /// GitHub answered the code exchange with an OAuth error. It does so with HTTP 200.
    #[error("GitHub rejected the code exchange")]
    Rejected(#[source] ProviderRejection),
    /// The access token is empty.
    #[error("GitHub returned an empty access token")]
    EmptyAccessToken,
    /// The access token is longer than we accept.
    #[error("GitHub access token is {0} bytes; at most {MAX_TOKEN_BYTES} are accepted")]
    AccessTokenTooLong(usize),
    /// GitHub returned the reserved user ID 0.
    #[error("GitHub user ID is zero")]
    ZeroUserId,
}

/// GitHub's API endpoints. They are `String`s so tests can use a local fixture.
#[derive(Clone)]
pub(in crate::federation) struct GitHubProtocol {
    /// Profile endpoint returning the numeric subject and names.
    pub(in crate::federation) user: String,
    /// Email endpoint; when GitHub denies access the identity simply has no email.
    pub(in crate::federation) emails: String,
}

impl ProviderEndpoints {
    /// GitHub's protocol facts.
    pub(super) fn github() -> Self {
        Self {
            issuer: "https://github.com",
            authorization: "https://github.com/login/oauth/authorize",
            token: "https://github.com/login/oauth/access_token".into(),
            scopes: SCOPES,
            identity: IdentityStrategy::GitHub(GitHubProtocol {
                user: "https://api.github.com/user".into(),
                emails: "https://api.github.com/user/emails?per_page=100".into(),
            }),
        }
    }
}

impl FederationApplication {
    /// Reads GitHub's numeric subject and, if shared, its verified primary email.
    pub(super) async fn github_identity(
        &self,
        response: reqwest::Response,
        protocol: &GitHubProtocol,
    ) -> Result<VerifiedIdentity, ProviderError> {
        let token = match Self::json(response).await? {
            GitHubTokenResponse::Token(token) => token.access_token,
            GitHubTokenResponse::Rejected(rejection) => {
                return Err(GitHubError::Rejected(rejection).into());
            }
        };
        if token.is_empty() {
            return Err(GitHubError::EmptyAccessToken.into());
        }
        if token.len() > MAX_TOKEN_BYTES {
            return Err(GitHubError::AccessTokenTooLong(token.len()).into());
        }
        let user: GitHubUser = Self::json(
            self.client
                .get(&protocol.user)
                .bearer_auth(&token)
                .send_traced()
                .await?,
        )
        .await?;
        if user.id == 0 {
            return Err(GitHubError::ZeroUserId.into());
        }
        let response = self
            .client
            .get(&protocol.emails)
            .bearer_auth(&token)
            .send_traced()
            .await?;
        // GitHub can withhold email access without invalidating its authenticated subject.
        let emails: Vec<GitHubEmail> = if response.status() == StatusCode::FORBIDDEN {
            Vec::new()
        } else {
            Self::json(response).await?
        };
        let email = emails
            .into_iter()
            .find(|email| email.verified && email.primary)
            .map(|email| email.email);
        VerifiedIdentity::new(user.id.to_string(), email, user.name, user.login)
    }
}

/// GitHub's code-exchange response: a token, or an OAuth error sent with HTTP 200.
#[derive(Deserialize)]
#[serde(untagged)]
enum GitHubTokenResponse {
    /// The exchange succeeded.
    Token(GitHubToken),
    /// GitHub refused the code, e.g. because it expired.
    Rejected(ProviderRejection),
}

/// A successful GitHub code exchange.
#[derive(Deserialize)]
struct GitHubToken {
    /// Bearer token, used only for GitHub API requests.
    access_token: String,
}

/// GitHub's authenticated user profile.
#[derive(Deserialize)]
struct GitHubUser {
    /// Stable numeric account ID; zero is invalid.
    id: u64,
    /// Profile name, often unset.
    name: Option<String>,
    /// Username, used as the display name when `name` is unset.
    login: String,
}

/// One address from GitHub's email list.
#[derive(Deserialize)]
struct GitHubEmail {
    /// Address as GitHub returns it, not yet normalized.
    email: String,
    /// Whether GitHub verified ownership of the address.
    verified: bool,
    /// Whether this is the account's primary address.
    primary: bool,
}
