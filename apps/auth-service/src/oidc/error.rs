//! OAuth protocol failures, keeping the cause of every rejection and internal error.

use super::ClientRedirect;
use crate::security::{ApiError, SessionError};
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use piquel_common::{
    ErrorChain,
    protocol::{
        challenge::{BearerChallenge, BearerError},
        oauth::{ErrorDescription, ErrorResponse},
    },
};
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;
use std::{borrow::Cow, error::Error as StdError};
use thiserror::Error;
use url::Url;

/// OAuth and OIDC error codes, shared with the SDKs through `piquel-common` and read by
/// the auth frontend's consent page.
pub(super) use piquel_common::protocol::oauth::ErrorCode as OAuthCode;

/// Builds rejections from an [`OAuthCode`]. A trait because the code type lives in
/// `piquel-common`; import it wherever rejections are built.
pub(super) trait Reject {
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
            source: Some(Box::new(error)),
        }
    }
}

/// Error of every OIDC endpoint, the consent page's JSON endpoints included: that page
/// already reads OAuth codes, so it does not use `ApiError` messages.
#[derive(Debug, Error)]
pub(super) enum OAuthError {
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
    /// A persisted or internally constructed URL could not be parsed.
    #[error("OIDC redirect URL is invalid")]
    Url(#[from] url::ParseError),
    /// A generated cookie could not be represented as an HTTP header.
    #[error("OIDC cookie header is invalid")]
    CookieHeader(#[from] axum::http::header::InvalidHeaderValue),
}

impl OAuthError {
    /// HTTP status of the JSON error response for `code`.
    /// Auth never sends a code it does not know, but the open vocabulary needs an
    /// answer for one.
    const fn status(code: &OAuthCode) -> StatusCode {
        match code {
            OAuthCode::InvalidClient | OAuthCode::InvalidToken => StatusCode::UNAUTHORIZED,
            OAuthCode::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            OAuthCode::InvalidRequest
            | OAuthCode::InvalidGrant
            | OAuthCode::InvalidScope
            | OAuthCode::InvalidTarget
            | OAuthCode::UnsupportedGrantType
            | OAuthCode::LoginRequired
            | OAuthCode::ConsentRequired
            | OAuthCode::RequestNotSupported
            | OAuthCode::RequestUriNotSupported
            | OAuthCode::AccessDenied
            | OAuthCode::Other(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// `WWW-Authenticate` challenge sent with failed client or bearer authentication.
    fn challenge(code: &OAuthCode) -> Option<String> {
        match code {
            OAuthCode::InvalidClient => Some("Basic realm=\"token\"".into()),
            OAuthCode::InvalidToken => {
                Some(BearerChallenge::error(BearerError::InvalidToken).to_string())
            }
            OAuthCode::InvalidRequest
            | OAuthCode::InvalidGrant
            | OAuthCode::InvalidScope
            | OAuthCode::InvalidTarget
            | OAuthCode::UnsupportedGrantType
            | OAuthCode::LoginRequired
            | OAuthCode::ConsentRequired
            | OAuthCode::RequestNotSupported
            | OAuthCode::RequestUriNotSupported
            | OAuthCode::AccessDenied
            | OAuthCode::ServerError
            | OAuthCode::Other(_) => None,
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
            | DatabaseError::Timeout(_)
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
                source,
                ..
            } => Self::Protocol {
                redirect: Some(Box::new(code.redirect_url(to, &description))),
                code,
                description,
                source,
            },
            error
            @ (Self::Database(_) | Self::Crypto(_) | Self::Url(_) | Self::CookieHeader(_)) => error,
        }
    }
}

impl IntoResponse for OAuthError {
    /// Redirects or answers with OAuth error JSON. Internal failures are logged as errors;
    /// rejections with a cause are logged at debug level, since clients trigger them.
    fn into_response(self) -> Response {
        let (code, description, redirect) = match &self {
            Self::Protocol {
                code,
                description,
                redirect,
                source,
            } => {
                if source.is_some() {
                    tracing::debug!(error = %ErrorChain(&self), "OAuth request rejected");
                }
                (code.clone(), description.as_ref(), redirect.as_ref())
            }
            Self::Database(_) | Self::Crypto(_) | Self::Url(_) | Self::CookieHeader(_) => {
                ApiError::log_error(&self);
                (
                    OAuthCode::ServerError,
                    "the request could not be completed; try again",
                    None,
                )
            }
        };
        if let Some(location) = redirect {
            return Redirect::to(location.as_str()).into_response();
        }
        let status = Self::status(&code);
        let challenge = Self::challenge(&code);
        let body = ErrorResponse {
            error: code,
            error_description: Some(ErrorDescription::lossy(description)),
        };
        let mut response = (status, Json(body)).into_response();
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

impl From<SessionError> for OAuthError {
    /// A missing session is `invalid_token`, as OIDC and the consent page expect.
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Missing => {
                OAuthCode::InvalidToken.reject_with("sign in to continue", error)
            }
            SessionError::StepUpRequired { .. } | SessionError::PasskeyRequired => {
                OAuthCode::InvalidToken.reject_with("confirm with a passkey to continue", error)
            }
            SessionError::Database(error) => Self::Database(error),
            SessionError::Crypto(error) => Self::Crypto(error),
        }
    }
}

impl From<piquel_repository::CodeRedemptionError> for OAuthError {
    /// Redemption failures reject the grant; persistence failures retain their internal status.
    fn from(error: piquel_repository::CodeRedemptionError) -> Self {
        match error {
            piquel_repository::CodeRedemptionError::Database(source) => source.into(),
            error @ piquel_repository::CodeRedemptionError::Invalid => OAuthCode::InvalidGrant
                .reject_with(
                    "code is unknown or expired, or its client, account or sign-in session no \
                     longer allows it",
                    error,
                ),
            error @ piquel_repository::CodeRedemptionError::Replay { .. } => {
                OAuthCode::InvalidGrant.reject_with(
                    "code was already used, so any refresh tokens issued from it are revoked",
                    error,
                )
            }
        }
    }
}

impl From<piquel_repository::RefreshRotationError> for OAuthError {
    /// Rotation failures reject the grant; persistence failures retain their internal status.
    fn from(error: piquel_repository::RefreshRotationError) -> Self {
        match error {
            piquel_repository::RefreshRotationError::Database(source) => source.into(),
            error @ piquel_repository::RefreshRotationError::Invalid => OAuthCode::InvalidGrant
                .reject_with("refresh_token is unknown, expired or revoked", error),
            error @ piquel_repository::RefreshRotationError::Replay { .. } => {
                OAuthCode::InvalidGrant.reject_with(
                    "refresh_token was already used, so its whole token family is now revoked",
                    error,
                )
            }
            error @ piquel_repository::RefreshRotationError::Policy { .. } => {
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
