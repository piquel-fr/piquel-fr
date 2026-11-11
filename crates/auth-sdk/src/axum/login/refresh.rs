//! Reading the request's session from its cookie, and refreshing its access token.
//!
//! The login routes take only confidential clients, whose refresh tokens auth does
//! not rotate, so concurrent requests may each refresh: every one gets valid tokens,
//! and the browser keeps whichever cookie arrives last. A failed refresh spends
//! nothing, so only auth's refusal ends the session; but an access token that
//! expired and could not be refreshed is never handed out, so a session auth ended
//! stops within an access token's lifetime even while auth is unreachable.

use super::{Login, SessionCookie, SignedIn, layer::RequestSession};
use crate::{
    OAuthError, TokenError,
    axum::StoredLogin,
    protocol::oauth::{ErrorCode, ErrorResponse},
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::TimeDelta;
use sourceorigin_common::ErrorChain;
use std::time::Duration;

/// Access tokens this close to expiry are refreshed first.
const REFRESH_MARGIN: TimeDelta = TimeDelta::seconds(30);
/// Longest a refresh may take, auth's response and its ID token check included.
const REFRESH_DEADLINE: Duration = Duration::from_secs(20);

/// What refreshing a session came to.
enum Refresh {
    /// New tokens.
    Refreshed(Box<StoredLogin>),
    /// Auth could not be asked, or answered with an error other than a refusal: the
    /// session goes on as it was, and a later request tries again.
    Kept,
    /// Auth refused the refresh token, or named another user or sign-in: the session
    /// is over.
    Ended,
}

/// The session's access token expired and could not be refreshed: the request is
/// refused for now, and the cookie kept for a later request to refresh.
#[derive(Clone, Copy, Debug)]
pub(super) struct Unavailable;

impl IntoResponse for Unavailable {
    /// 503, for the browser to try again.
    fn into_response(self) -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Your session could not be renewed; try again in a moment.",
        )
            .into_response()
    }
}

impl Login {
    /// The signed-in user the request's session cookie holds, its access token
    /// refreshed when it is about to expire. Records in `request` the cookie the
    /// response must set: the refreshed session, or the deletion of an ended one.
    ///
    /// # Errors
    /// [`Unavailable`] when the access token expired and auth could not renew it.
    pub(super) async fn session(
        &self,
        headers: &HeaderMap,
        request: &RequestSession,
    ) -> Result<Option<SignedIn>, Unavailable> {
        let mut login = match self.open_session(headers) {
            SessionCookie::Absent => return Ok(None),
            SessionCookie::Ended => {
                request.set_cookie(Self::clear_cookie(&self.cookies.session));
                return Ok(None);
            }
            SessionCookie::Open(login) => *login,
        };
        if login.refresh_token().is_some() && login.expires_at() <= self.now() + REFRESH_MARGIN {
            match self.refresh(&login).await {
                Refresh::Refreshed(refreshed) => {
                    let refreshed = *refreshed;
                    // On failure, as when new profile claims outgrow the cookie, this
                    // request still uses the new tokens, and the next refreshes again.
                    match self.session_cookie(&refreshed) {
                        Ok(cookie) => request.set_cookie(cookie),
                        Err(error) => tracing::warn!(
                            error = %ErrorChain(&error),
                            "the refreshed session could not be saved"
                        ),
                    }
                    login = refreshed;
                }
                Refresh::Kept if login.expires_at() <= self.now() => return Err(Unavailable),
                Refresh::Kept => {}
                Refresh::Ended => {
                    request.set_cookie(Self::clear_cookie(&self.cookies.session));
                    return Ok(None);
                }
            }
        }
        // The session may have reached its end while the refresh ran.
        let now = self.now();
        if login.ends_at() <= now {
            request.set_cookie(Self::clear_cookie(&self.cookies.session));
            return Ok(None);
        }
        Ok(Some(SignedIn {
            login,
            checked_at: now,
            retry: request.retry,
        }))
    }

    /// Refreshes the session's access token.
    async fn refresh(&self, login: &StoredLogin) -> Refresh {
        let Some(refresh_token) = login.refresh_token() else {
            return Refresh::Kept;
        };
        let refreshing = self.client.refresh(refresh_token, login.claims());
        let Ok(refreshed) = tokio::time::timeout(REFRESH_DEADLINE, refreshing).await else {
            tracing::warn!("session refresh timed out");
            return Refresh::Kept;
        };
        match refreshed {
            Ok(tokens) => Refresh::Refreshed(Box::new(login.refreshed(tokens))),
            // The new ID token names another user or another sign-in (OIDC Core
            // §12.2): the session cannot go on as either.
            Err(OAuthError::IdToken(
                error @ (TokenError::SubjectMismatch { .. } | TokenError::AuthenticationChanged(_)),
            )) => {
                tracing::warn!(error = %ErrorChain(&error), "a refresh changed the signed-in user or sign-in");
                Refresh::Ended
            }
            // Auth refused the refresh token: the grant is over.
            Err(
                error @ OAuthError::Rejected {
                    response:
                        ErrorResponse {
                            error: ErrorCode::InvalidGrant,
                            ..
                        },
                    ..
                },
            ) => {
                tracing::debug!(error = %ErrorChain(&error), "session refresh refused");
                Refresh::Ended
            }
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), "session refresh failed");
                Refresh::Kept
            }
        }
    }
}
