//! A typed client of the admin API, behind the `client` feature. The dashboard calls
//! it from its server with the signed-in administrator's access token.

use super::{
    Administrator, Client, CreateInvitation, CreatedInvitation, DisableUser, ErrorBody, EventPage,
    EventSearch, GrantAdministrator, Invitation, RenameHandle, UserDetail, UserPage, UserSearch,
    paths,
};
use piquel_common::{
    Handle, SessionId, TokenId, UserId,
    protocol::{
        challenge::{BearerChallenge, BearerError},
        step_up::StepUpRequirement,
    },
};
use reqwest::{Method, RequestBuilder, StatusCode, header};
use serde::de::DeserializeOwned;
use std::{fmt::Display, time::Duration};
use url::Url;

/// Longest an admin API call may take. The API answers from one database query or
/// transaction, so anything slower has failed.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Why an admin API call failed.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The API asks for another sign-in (`401` with an RFC 6750 or RFC 9470
    /// challenge): the token is missing, invalid or from an ended session, or its
    /// sign-in is too weak or too old for the call. Holds what the new sign-in must
    /// meet, which is nothing in particular when the token was merely invalid.
    #[error("the admin API asks to sign in again")]
    SignIn(StepUpRequirement),
    /// The API refused the call, e.g. `403` for a non-administrator or `409` for an
    /// account already disabled.
    #[error("the admin API refused the call ({status}): {}", .body.error)]
    Refused {
        /// The response status.
        status: StatusCode,
        /// The API's explanation.
        body: ErrorBody,
    },
    /// The API could not be reached, or answered outside its contract. The error
    /// keeps no URL: account searches carry names and emails in their query, and
    /// failures are logged and exported.
    #[error("the admin API could not be reached")]
    Unreachable(#[source] reqwest::Error),
    /// The API answered with a body this version cannot read.
    #[error("the admin API answered {status} with an unexpected body")]
    InvalidResponse {
        /// The response status.
        status: StatusCode,
        /// Why the body did not decode.
        #[source]
        source: serde_json::Error,
    },
}

impl From<reqwest::Error> for ApiError {
    /// Drops the request URL, keeping every other cause.
    fn from(error: reqwest::Error) -> Self {
        Self::Unreachable(error.without_url())
    }
}

impl ApiError {
    /// The response status, when the API answered.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::SignIn(_) => Some(StatusCode::UNAUTHORIZED),
            Self::Refused { status, .. } | Self::InvalidResponse { status, .. } => Some(*status),
            Self::Unreachable(error) => error.status(),
        }
    }
}

/// The admin API at one base URL, such as `http://auth:8081`.
#[derive(Clone, Debug)]
pub struct AdminClient {
    /// Connection pool for every call.
    http: reqwest::Client,
    /// Where the API listens; paths are appended to it.
    base: Url,
}

impl AdminClient {
    /// A client of the API at `base`.
    ///
    /// # Errors
    /// [`ApiError::Unreachable`] if the HTTP client cannot be built, e.g. without TLS
    /// roots.
    pub fn new(base: Url) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // The API never redirects.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { http, base })
    }

    /// Searches accounts.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn search_users(
        &self,
        token: &str,
        search: &UserSearch,
    ) -> Result<UserPage, ApiError> {
        self.send(
            self.request(token, Method::GET, paths::USERS, &[])
                .query(search),
        )
        .await
    }

    /// Describes one account.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn user(&self, token: &str, user: UserId) -> Result<UserDetail, ApiError> {
        self.send(self.request(token, Method::GET, paths::USER, &[&user]))
            .await
    }

    /// Disables an account and ends its sessions.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn disable_user(
        &self,
        token: &str,
        user: UserId,
        input: &DisableUser,
    ) -> Result<(), ApiError> {
        self.send(
            self.request(token, Method::POST, paths::USER_DISABLE, &[&user])
                .json(input),
        )
        .await
    }

    /// Reactivates a disabled account.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn enable_user(&self, token: &str, user: UserId) -> Result<(), ApiError> {
        self.send(self.request(token, Method::POST, paths::USER_ENABLE, &[&user]))
            .await
    }

    /// Ends every session and refresh grant of an account.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn revoke_user_sessions(&self, token: &str, user: UserId) -> Result<(), ApiError> {
        self.send(self.request(token, Method::DELETE, paths::USER_SESSIONS, &[&user]))
            .await
    }

    /// Gives an account a new handle. Operators skip the rename cooldown.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn rename_handle(
        &self,
        token: &str,
        user: UserId,
        input: &RenameHandle,
    ) -> Result<(), ApiError> {
        self.send(
            self.request(token, Method::PUT, paths::USER_HANDLE, &[&user])
                .json(input),
        )
        .await
    }

    /// Deletes a released handle, so anyone may claim it again.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn release_handle(&self, token: &str, handle: &Handle) -> Result<(), ApiError> {
        self.send(self.request(token, Method::DELETE, paths::HANDLE, &[handle]))
            .await
    }

    /// Ends one session and its refresh grants.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn revoke_session(&self, token: &str, session: SessionId) -> Result<(), ApiError> {
        self.send(self.request(token, Method::DELETE, paths::SESSION, &[&session]))
            .await
    }

    /// Lists invitations. Auth answers `404` while signup needs no invitation.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn invitations(&self, token: &str) -> Result<Vec<Invitation>, ApiError> {
        self.send(self.request(token, Method::GET, paths::INVITATIONS, &[]))
            .await
    }

    /// Creates an invitation, whose link is returned only this once.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn create_invitation(
        &self,
        token: &str,
        input: &CreateInvitation,
    ) -> Result<CreatedInvitation, ApiError> {
        self.send(
            self.request(token, Method::POST, paths::INVITATIONS, &[])
                .json(input),
        )
        .await
    }

    /// Revokes an unredeemed invitation.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn revoke_invitation(
        &self,
        token: &str,
        invitation: TokenId,
    ) -> Result<(), ApiError> {
        self.send(self.request(token, Method::DELETE, paths::INVITATION, &[&invitation]))
            .await
    }

    /// Lists OIDC clients.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn clients(&self, token: &str) -> Result<Vec<Client>, ApiError> {
        self.send(self.request(token, Method::GET, paths::CLIENTS, &[]))
            .await
    }

    /// Pages through domain events, newest first.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn events(&self, token: &str, search: &EventSearch) -> Result<EventPage, ApiError> {
        self.send(
            self.request(token, Method::GET, paths::EVENTS, &[])
                .query(search),
        )
        .await
    }

    /// Lists administrators.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn administrators(&self, token: &str) -> Result<Vec<Administrator>, ApiError> {
        self.send(self.request(token, Method::GET, paths::ADMINISTRATORS, &[]))
            .await
    }

    /// Makes an account an administrator.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn grant_administrator(
        &self,
        token: &str,
        input: &GrantAdministrator,
    ) -> Result<(), ApiError> {
        self.send(
            self.request(token, Method::POST, paths::ADMINISTRATORS, &[])
                .json(input),
        )
        .await
    }

    /// Removes another administrator's rights.
    ///
    /// # Errors
    /// See [`ApiError`].
    pub async fn revoke_administrator(&self, token: &str, user: UserId) -> Result<(), ApiError> {
        self.send(self.request(token, Method::DELETE, paths::ADMINISTRATOR, &[&user]))
            .await
    }

    /// The URL of `template` with its `{…}` segments replaced by `params`, in order.
    /// Each value fills one percent-encoded segment.
    fn url(&self, template: &str, params: &[&(dyn Display + Sync)]) -> Url {
        let mut url = self.base.clone();
        let mut params = params.iter();
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.pop_if_empty();
            for segment in template.split('/').filter(|segment| !segment.is_empty()) {
                match segment.starts_with('{').then(|| params.next()).flatten() {
                    Some(param) => segments.push(&param.to_string()),
                    None => segments.push(segment),
                };
            }
        }
        url
    }

    /// A request to `template` as the token's administrator.
    fn request(
        &self,
        token: &str,
        method: Method,
        template: &str,
        params: &[&(dyn Display + Sync)],
    ) -> RequestBuilder {
        self.http
            .request(method, self.url(template, params))
            .bearer_auth(token)
    }

    /// Sends `request` and decodes its answer: JSON, or nothing for `204`, which
    /// decodes as `()`.
    async fn send<R: DeserializeOwned>(&self, request: RequestBuilder) -> Result<R, ApiError> {
        let response = request.send().await?;
        let status = response.status();
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<BearerChallenge>().ok());
        let bytes = response.bytes().await?;
        match challenge {
            Some(challenge)
                if status == StatusCode::UNAUTHORIZED
                    && challenge.error != Some(BearerError::InvalidRequest) =>
            {
                Err(ApiError::SignIn(challenge.step_up))
            }
            _ if status.is_success() => {
                serde_json::from_slice(if bytes.is_empty() { b"null" } else { &bytes })
                    .map_err(|source| ApiError::InvalidResponse { status, source })
            }
            // A route auth does not serve, such as invitations while signup is open,
            // answers without a body.
            _ => Err(ApiError::Refused {
                status,
                body: serde_json::from_slice(&bytes).unwrap_or_else(|_| ErrorBody {
                    error: status.canonical_reason().unwrap_or("error").to_lowercase(),
                    code: None,
                }),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    //! URL building.
    use super::*;

    /// Parameters fill their template segments percent-encoded, under the base
    /// URL's own path.
    #[test]
    fn urls_fill_parameters() {
        let client =
            AdminClient::new("http://auth:8081/admin/".parse().expect("url")).expect("client");
        let user = UserId::new();
        assert_eq!(
            client.url(paths::USER_DISABLE, &[&user]).as_str(),
            format!("http://auth:8081/admin/users/{user}/disable"),
        );
        assert_eq!(
            client.url(paths::CLIENT, &[&"a/b c"]).as_str(),
            "http://auth:8081/admin/clients/a%2Fb%20c",
        );
    }

    /// A failed call reports no part of its URL, whose query can hold an email.
    #[tokio::test]
    async fn failures_omit_the_query() {
        // Nothing listens on the discard port.
        let client = AdminClient::new("http://127.0.0.1:9/".parse().expect("url")).expect("client");
        let search = UserSearch {
            q: "person@example.com".into(),
            cursor: None,
        };
        let error = client
            .search_users("token", &search)
            .await
            .expect_err("unreachable");
        let chain = piquel_common::ErrorChain(&error).to_string();
        assert!(matches!(error, ApiError::Unreachable(_)), "{chain}");
        assert!(!chain.contains("example.com"), "{chain}");
    }
}
