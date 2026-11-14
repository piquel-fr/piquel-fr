//! OAuth protocol failures, keeping the cause of every rejection and internal error.

use super::ClientRedirect;
use crate::{
    keys::StaleKeys,
    security::{ApiError, Explanation, SessionError},
};
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use sourceorigin_common::{
    ErrorChain,
    protocol::{
        challenge::BearerChallenge,
        oauth::{ErrorDescription, ErrorResponse, InvalidScope},
    },
};
use sourceorigin_crypto::CryptoError;
use sourceorigin_repository::DatabaseError;
use sourceorigin_ui::QueryError;
use std::{borrow::Cow, error::Error as StdError};
use thiserror::Error;
use url::Url;

/// OAuth and OIDC error codes, shared with the SDKs through `sourceorigin-common` and shown by
/// auth's consent and logout pages.
pub(crate) use sourceorigin_common::protocol::oauth::ErrorCode as OAuthCode;

/// Builds rejections from an [`OAuthCode`]. A trait because the code type lives in
/// `sourceorigin-common`; import it wherever rejections are built.
pub(crate) trait Reject {
    /// Client redirect carrying this error code and its description.
    fn redirect_url(&self, to: &ClientRedirect<'_>, description: &str) -> Url;

    /// Rejects the request with this code. `description` tells the client what to fix;
    /// it must not reveal secrets or whether a credential exists.
    fn reject(self, description: impl Into<Cow<'static, str>>) -> OAuthError;

    /// Like [`Self::reject`], keeping the parse or verification error for logs.
    fn reject_with(
        self,
        description: impl Into<Cow<'static, str>>,
        error: impl StdError + Send + Sync + 'static,
    ) -> OAuthError;
}

impl Reject for OAuthCode {
    fn redirect_url(&self, to: &ClientRedirect<'_>, description: &str) -> Url {
        to.url(&[
            ("error", self.as_str()),
            (
                "error_description",
                ErrorDescription::lossy(description).as_str(),
            ),
        ])
    }

    fn reject(self, description: impl Into<Cow<'static, str>>) -> OAuthError {
        OAuthError::Protocol {
            code: self,
            description: description.into(),
            redirect: None,
            challenge: None,
            source: None,
        }
    }

    fn reject_with(
        self,
        description: impl Into<Cow<'static, str>>,
        error: impl StdError + Send + Sync + 'static,
    ) -> OAuthError {
        OAuthError::Protocol {
            code: self,
            description: description.into(),
            redirect: None,
            challenge: None,
            source: Some(Box::new(error)),
        }
    }
}

/// The `WWW-Authenticate` challenge a rejected credential is answered with (RFC 9110
/// §11.6.1), naming the scheme the request used, or should have.
#[derive(Debug)]
pub(crate) enum Challenge {
    /// The client sent an `Authorization` header to authenticate itself, where only
    /// HTTP Basic is accepted (RFC 6749 §5.2).
    Basic,
    /// A bearer token at `UserInfo`, missing or rejected (RFC 6750 §3).
    Bearer(BearerChallenge),
}

impl Challenge {
    /// The HTTP status the challenge is sent with: 401, or 403 for a token that
    /// lacks a scope.
    fn status(&self) -> StatusCode {
        match self {
            Self::Basic => StatusCode::UNAUTHORIZED,
            Self::Bearer(challenge) => {
                StatusCode::from_u16(challenge.status()).unwrap_or(StatusCode::UNAUTHORIZED)
            }
        }
    }

    /// The header value.
    fn header(&self) -> String {
        match self {
            Self::Basic => format!("{} realm=\"token\"", super::AuthScheme::Basic),
            Self::Bearer(challenge) => challenge.to_string(),
        }
    }
}

/// Error of every OIDC endpoint and of the consent and logout pages, which show what
/// its OAuth code means rather than an `ApiError` message.
#[derive(Debug, Error)]
pub(crate) enum OAuthError {
    /// The request was rejected with `code` and `description`. The cause, if any, is
    /// logged but never sent.
    #[error("OAuth request rejected with {code}: {description}")]
    Protocol {
        /// Code sent to the client.
        code: OAuthCode,
        /// Sent to the client as `error_description`.
        description: Cow<'static, str>,
        /// Client redirect carrying the error; only set once the redirect URI is verified.
        /// Boxed to keep `Result<_, OAuthError>` small.
        redirect: Option<Box<Url>>,
        /// The challenge of a rejected credential. Boxed for the same reason.
        challenge: Option<Box<Challenge>>,
        /// Why the input was rejected.
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
    /// A database operation failed.
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// Signing, hashing or random generation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// This replica's signing keys are stale, so it neither signs nor verifies.
    #[error(transparent)]
    Keys(#[from] StaleKeys),
    /// A persisted or internally constructed URL could not be parsed.
    #[error("OIDC redirect URL is invalid")]
    Url(#[from] url::ParseError),
    /// A generated cookie could not be represented as an HTTP header.
    #[error("OIDC cookie header is invalid")]
    CookieHeader(#[from] axum::http::header::InvalidHeaderValue),
    /// The address of the page the browser goes on to could not be written.
    #[error("a page's address could not be written")]
    PageAddress(#[from] QueryError),
    /// A grant read back from the database holds an invalid scope.
    #[error("a stored grant holds an invalid scope")]
    StoredScopes(#[from] InvalidScope),
}

impl OAuthError {
    /// HTTP status of the error response for `code`, when no credential is
    /// challenged: a challenge decides it otherwise. Nothing is 401 without a
    /// challenge, which RFC 9110 §15.5.2 requires of a 401: `invalid_client` is
    /// 400 when the client sent no `Authorization` header (RFC 6749 §5.2), and a
    /// page refusing the browser's session is 403.
    /// Auth never sends a code it does not know, but the open vocabulary needs an
    /// answer for one.
    const fn status(code: &OAuthCode) -> StatusCode {
        match code {
            OAuthCode::InvalidToken | OAuthCode::InsufficientScope => StatusCode::FORBIDDEN,
            OAuthCode::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthCode::InvalidRequest
            | OAuthCode::InvalidClient
            | OAuthCode::UnauthorizedClient
            | OAuthCode::InvalidGrant
            | OAuthCode::InvalidScope
            | OAuthCode::InvalidTarget
            | OAuthCode::UnsupportedGrantType
            | OAuthCode::UnsupportedResponseType
            | OAuthCode::LoginRequired
            | OAuthCode::ConsentRequired
            | OAuthCode::UnmetAuthenticationRequirements
            | OAuthCode::RequestNotSupported
            | OAuthCode::InvalidRequestUri
            | OAuthCode::AccessDenied
            | OAuthCode::Other(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Answers the rejection with `challenge`, which then sets its status.
    pub(super) fn challenged(self, challenge: Challenge) -> Self {
        match self {
            Self::Protocol {
                code,
                description,
                redirect,
                source,
                ..
            } => Self::Protocol {
                code,
                description,
                redirect,
                challenge: Some(Box::new(challenge)),
                source,
            },
            error @ (Self::Database(_)
            | Self::Crypto(_)
            | Self::Keys(_)
            | Self::Url(_)
            | Self::CookieHeader(_)
            | Self::PageAddress(_)
            | Self::StoredScopes(_)) => error,
        }
    }

    /// Turns a missing or already consumed record into `expected` with `description`;
    /// other failures stay internal.
    pub(super) fn database(
        error: DatabaseError,
        expected: OAuthCode,
        description: &'static str,
    ) -> Self {
        match error {
            DatabaseError::NotFound => expected.reject_with(description, error),
            DatabaseError::Conflict(_)
            | DatabaseError::Refused(_)
            | DatabaseError::Timeout(_)
            | DatabaseError::Cancelled(_)
            | DatabaseError::LockUnavailable(_)
            | DatabaseError::InvalidStoredData { .. }
            | DatabaseError::Operation(_) => Self::Database(error),
        }
    }

    /// Sends a rejection back to the client's verified redirect URI.
    /// Internal failures stay JSON 500 responses.
    pub(super) fn redirected(self, to: &ClientRedirect<'_>) -> Self {
        match self {
            Self::Protocol {
                code,
                description,
                challenge,
                source,
                ..
            } => Self::Protocol {
                redirect: Some(Box::new(code.redirect_url(to, &description))),
                code,
                description,
                challenge,
                source,
            },
            error @ (Self::Database(_)
            | Self::Crypto(_)
            | Self::Keys(_)
            | Self::Url(_)
            | Self::CookieHeader(_)
            | Self::PageAddress(_)
            | Self::StoredScopes(_)) => error,
        }
    }
}

impl OAuthError {
    /// What the client is told: the status, the code and its description. Internal
    /// failures become `server_error` and are logged as errors, with `503` when
    /// this replica's signing keys are stale, since another replica may serve the
    /// request; rejections with a cause are logged at debug level, since clients
    /// trigger them.
    pub(crate) fn public(&self) -> (StatusCode, OAuthCode, &str) {
        let (code, description) = match self {
            Self::Protocol {
                code,
                description,
                challenge,
                source,
                ..
            } => {
                if source.is_some() {
                    tracing::debug!(error = %ErrorChain(self), "OAuth request rejected");
                }
                let status = challenge
                    .as_ref()
                    .map_or_else(|| Self::status(code), |challenge| challenge.status());
                return (status, code.clone(), description.as_ref());
            }
            Self::Keys(_) => {
                ApiError::log_error(self);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    OAuthCode::ServerError,
                    "signing keys are unavailable; try again",
                );
            }
            Self::Database(_)
            | Self::Crypto(_)
            | Self::Url(_)
            | Self::CookieHeader(_)
            | Self::PageAddress(_)
            | Self::StoredScopes(_) => {
                ApiError::log_error(self);
                (
                    OAuthCode::ServerError,
                    "the request could not be completed; try again",
                )
            }
        };
        (Self::status(&code), code, description)
    }
}

impl IntoResponse for OAuthError {
    /// Redirects to the client, or answers with OAuth error JSON, whose
    /// description a browser navigating here, as to the authorization endpoint,
    /// reads on its error page.
    fn into_response(self) -> Response {
        let (status, code, description) = self.public();
        if let Self::Protocol {
            redirect: Some(location),
            ..
        } = &self
        {
            return Redirect::to(location.as_str()).into_response();
        }
        let challenge = if let Self::Protocol {
            challenge: Some(challenge),
            ..
        } = &self
        {
            Some(challenge.header())
        } else {
            None
        };
        let explanation = Explanation(format!("The app's request was refused: {description}."));
        let body = ErrorResponse {
            error: code,
            error_description: Some(ErrorDescription::lossy(description)),
        };
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(explanation);
        if let Some(challenge) =
            challenge.and_then(|challenge| HeaderValue::try_from(challenge).ok())
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, challenge);
        }
        response
    }
}

impl From<OAuthError> for ApiError {
    /// A rejection reaching a browser API, such as inline sign-in's, is a 400 that
    /// explains it; internal failures stay internal.
    fn from(error: OAuthError) -> Self {
        match error {
            OAuthError::Protocol { description, .. } => Self::bad_request(description),
            OAuthError::Database(error) => error.into(),
            OAuthError::Keys(error) => error.into(),
            error @ (OAuthError::Crypto(_)
            | OAuthError::Url(_)
            | OAuthError::CookieHeader(_)
            | OAuthError::PageAddress(_)
            | OAuthError::StoredScopes(_)) => Self::internal(error),
        }
    }
}

impl From<SessionError> for OAuthError {
    /// A missing session is `invalid_token`, as OIDC and the consent page expect.
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Missing => {
                OAuthCode::InvalidToken.reject_with("sign in to continue", error)
            }
            SessionError::StepUpRequired { .. }
            | SessionError::PasskeyRequired
            | SessionError::SignOutFirst => {
                OAuthCode::InvalidToken.reject_with("confirm with a passkey to continue", error)
            }
            SessionError::Database(error) => Self::Database(error),
            SessionError::Crypto(error) => Self::Crypto(error),
        }
    }
}

impl From<sourceorigin_repository::CodeRedemptionError> for OAuthError {
    /// Redemption failures reject the grant; persistence failures retain their internal status.
    fn from(error: sourceorigin_repository::CodeRedemptionError) -> Self {
        match error {
            sourceorigin_repository::CodeRedemptionError::Database(source) => source.into(),
            error @ sourceorigin_repository::CodeRedemptionError::Invalid => {
                OAuthCode::InvalidGrant.reject_with(
                    "code is unknown or expired, or its client, account or sign-in session no \
                     longer allows it",
                    error,
                )
            }
            error @ sourceorigin_repository::CodeRedemptionError::Replay { .. } => {
                OAuthCode::InvalidGrant.reject_with(
                    "code was already used, so any refresh tokens issued from it are revoked",
                    error,
                )
            }
        }
    }
}

impl From<sourceorigin_repository::RefreshRedemptionError> for OAuthError {
    /// Redemption failures reject the grant; persistence failures retain their internal status.
    fn from(error: sourceorigin_repository::RefreshRedemptionError) -> Self {
        match error {
            sourceorigin_repository::RefreshRedemptionError::Database(source) => source.into(),
            error @ sourceorigin_repository::RefreshRedemptionError::Invalid => {
                OAuthCode::InvalidGrant
                    .reject_with("refresh_token is unknown, expired or revoked", error)
            }
            error @ sourceorigin_repository::RefreshRedemptionError::Replay { .. } => {
                OAuthCode::InvalidGrant.reject_with(
                    "refresh_token was already used, so its whole token family is now revoked",
                    error,
                )
            }
            error @ sourceorigin_repository::RefreshRedemptionError::Policy { .. } => {
                OAuthCode::InvalidGrant.reject_with(
                    "the client or account no longer allows this grant, so its token family \
                     is now revoked",
                    error,
                )
            }
        }
    }
}

/// Failure to build the provider's public documents at startup.
#[derive(Debug, Error)]
pub enum OidcConfigError {
    /// The documentation link is not an absolute URL.
    #[error("the service documentation link is not a URL")]
    Documentation(#[source] url::ParseError),
    /// A public document could not be serialized.
    #[error("could not serialize a public OIDC document")]
    Serialize(#[from] serde_json::Error),
}
