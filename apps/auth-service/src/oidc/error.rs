//! OAuth protocol failures, keeping the cause of every rejection and internal error.

use crate::security::{ApiError, SessionError};
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use piquel_common::ErrorChain;
use piquel_crypto::CryptoError;
use piquel_repository::DatabaseError;
use serde_json::json;
use std::error::Error as StdError;
use thiserror::Error;
use url::Url;

piquel_common::str_enum! {
    /// OAuth and OIDC error codes, read by clients and by the auth frontend's consent page.
    pub(super) enum OAuthCode {
        /// Request parameters break the endpoint's contract.
        InvalidRequest = "invalid_request",
        /// Client authentication failed.
        InvalidClient = "invalid_client",
        /// An authorization code or refresh token is unusable.
        InvalidGrant = "invalid_grant",
        /// Requested scopes exceed the grant or the client's policy.
        InvalidScope = "invalid_scope",
        /// The requested audience is not registered for the client.
        InvalidTarget = "invalid_target",
        /// Bearer or browser authentication failed.
        InvalidToken = "invalid_token",
        /// The token endpoint does not support the requested grant.
        UnsupportedGrantType = "unsupported_grant_type",
        /// A `prompt=none` request needs the user to sign in.
        LoginRequired = "login_required",
        /// A `prompt=none` request needs the user's consent.
        ConsentRequired = "consent_required",
        /// Signed `request` objects are not supported.
        RequestNotSupported = "request_not_supported",
        /// `request_uri` references are not supported.
        RequestUriNotSupported = "request_uri_not_supported",
        /// The user declined consent.
        AccessDenied = "access_denied",
        /// An internal operation failed.
        ServerError = "server_error",
    }
}

impl OAuthCode {
    /// HTTP status of the JSON error response.
    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidRequest
            | Self::InvalidGrant
            | Self::InvalidScope
            | Self::InvalidTarget
            | Self::UnsupportedGrantType
            | Self::LoginRequired
            | Self::ConsentRequired
            | Self::RequestNotSupported
            | Self::RequestUriNotSupported
            | Self::AccessDenied => StatusCode::BAD_REQUEST,
        }
    }

    /// `WWW-Authenticate` challenge sent with failed client or bearer authentication.
    const fn challenge(self) -> Option<&'static str> {
        match self {
            Self::InvalidClient => Some("Basic realm=\"token\""),
            Self::InvalidToken => Some("Bearer error=\"invalid_token\""),
            Self::InvalidRequest
            | Self::InvalidGrant
            | Self::InvalidScope
            | Self::InvalidTarget
            | Self::UnsupportedGrantType
            | Self::LoginRequired
            | Self::ConsentRequired
            | Self::RequestNotSupported
            | Self::RequestUriNotSupported
            | Self::AccessDenied
            | Self::ServerError => None,
        }
    }

    /// Adds this error code and the client's `state` to a client redirect URI.
    pub(super) fn redirect_url(self, base: &Url, state: &str) -> Url {
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("error", self.as_str())
            .append_pair("state", state);
        url
    }
}

/// Error of every OIDC endpoint, the consent page's JSON endpoints included: that page
/// already reads OAuth codes, so it does not use `ApiError` messages.
#[derive(Debug, Error)]
pub(super) enum OAuthError {
    /// The request was rejected with `code`. The cause, if any, is logged but never sent.
    #[error("OAuth request rejected: {code}")]
    Protocol {
        /// Code sent to the client.
        code: OAuthCode,
        /// Client redirect carrying the error; only set once the redirect URI is verified.
        redirect: Option<Url>,
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

impl From<OAuthCode> for OAuthError {
    /// Rejects a request that broke a rule, with no underlying error to keep.
    fn from(code: OAuthCode) -> Self {
        Self::Protocol {
            code,
            redirect: None,
            source: None,
        }
    }
}

impl OAuthError {
    /// Rejects the request with `code`, keeping the parse or verification error for logs.
    pub(super) fn rejected(code: OAuthCode, error: impl StdError + Send + Sync + 'static) -> Self {
        Self::Protocol {
            code,
            redirect: None,
            source: Some(Box::new(error)),
        }
    }

    /// Turns a missing or already consumed record into `expected`; other failures stay internal.
    pub(super) fn database(error: DatabaseError, expected: OAuthCode) -> Self {
        match error {
            DatabaseError::NotFound => Self::rejected(expected, error),
            DatabaseError::Conflict(_)
            | DatabaseError::Timeout(_)
            | DatabaseError::InvalidStoredData { .. }
            | DatabaseError::Operation(_) => Self::Database(error),
        }
    }

    /// Sends a rejection back to the client's verified redirect URI with its `state`.
    /// Internal failures stay JSON 500 responses.
    pub(super) fn redirected(self, base: &Url, state: &str) -> Self {
        match self {
            Self::Protocol { code, source, .. } => Self::Protocol {
                code,
                redirect: Some(code.redirect_url(base, state)),
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
        let (code, redirect) = match &self {
            Self::Protocol {
                code,
                redirect,
                source,
            } => {
                if source.is_some() {
                    tracing::debug!(error = %ErrorChain(&self), "OAuth request rejected");
                }
                (*code, redirect.as_ref())
            }
            Self::Database(_) | Self::Crypto(_) | Self::Url(_) | Self::CookieHeader(_) => {
                ApiError::log_error(&self);
                (OAuthCode::ServerError, None)
            }
        };
        if let Some(location) = redirect {
            return Redirect::to(location.as_str()).into_response();
        }
        let mut response = (code.status(), Json(json!({"error":code}))).into_response();
        if let Some(challenge) = code.challenge() {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        response
    }
}

impl From<SessionError> for OAuthError {
    /// A missing session is `invalid_token`, as OIDC and the consent page expect.
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::Missing | SessionError::ManagementRequired => {
                Self::rejected(OAuthCode::InvalidToken, error)
            }
            SessionError::Database(error) => Self::Database(error),
            SessionError::Crypto(error) => Self::Crypto(error),
        }
    }
}

impl From<piquel_repository::RefreshRotationError> for OAuthError {
    /// Rotation failures reject the grant; persistence failures retain their internal status.
    fn from(error: piquel_repository::RefreshRotationError) -> Self {
        match error {
            piquel_repository::RefreshRotationError::Database(source) => source.into(),
            error @ (piquel_repository::RefreshRotationError::Invalid
            | piquel_repository::RefreshRotationError::Replay { .. }
            | piquel_repository::RefreshRotationError::Policy { .. }) => {
                Self::rejected(OAuthCode::InvalidGrant, error)
            }
        }
    }
}
