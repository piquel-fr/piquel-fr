//! OAuth protocol errors.

use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;
use url::Url;

/// OAuth 2.0 and OIDC error codes returned by this provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OAuthCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    InvalidTarget,
    InvalidToken,
    UnsupportedGrantType,
    LoginRequired,
    ConsentRequired,
    RequestNotSupported,
    RequestUriNotSupported,
    ServerError,
}
impl OAuthCode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidToken => "invalid_token",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::ServerError => "server_error",
        }
    }
    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient | Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
    /// `WWW-Authenticate` challenge for failed client or bearer-token authentication.
    const fn challenge(self) -> Option<&'static str> {
        match self {
            Self::InvalidClient => Some("Basic realm=\"token\""),
            Self::InvalidToken => Some("Bearer error=\"invalid_token\""),
            _ => None,
        }
    }
}
/// A protocol failure, answered with `{"error": code}` or by redirecting to the client.
///
/// Browser-facing account APIs use `security::ApiError` instead; OIDC clients and the
/// auth pages rely on these machine-readable codes.
#[derive(Debug)]
pub(super) struct OAuthError {
    code: OAuthCode,
    redirect: Option<Url>,
}
impl From<OAuthCode> for OAuthError {
    fn from(code: OAuthCode) -> Self {
        Self {
            code,
            redirect: None,
        }
    }
}
impl OAuthError {
    pub(super) fn internal(error: impl std::fmt::Debug) -> Self {
        tracing::error!(error=?error,"OIDC operation failed");
        OAuthCode::ServerError.into()
    }
    pub(super) fn database(error: piquel_repository::DatabaseError, expected: OAuthCode) -> Self {
        match error {
            piquel_repository::DatabaseError::NotFound => expected.into(),
            error => Self::internal(error),
        }
    }
    /// Returns `code` to a validated client redirect URI with its `state`.
    pub(super) fn redirect(base: &Url, code: OAuthCode, state: &str) -> Self {
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("error", code.as_str())
            .append_pair("state", state);
        Self {
            code,
            redirect: Some(url),
        }
    }
}
impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        if let Some(location) = self.redirect {
            return Redirect::to(location.as_str()).into_response();
        }
        let mut response = (
            self.code.status(),
            Json(json!({"error":self.code.as_str()})),
        )
            .into_response();
        if let Some(challenge) = self.code.challenge() {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(challenge),
            );
        }
        response
    }
}
