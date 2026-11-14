//! The routes' handlers: starting a login, completing it, and both logouts.

use super::{
    Login, MAX_PENDING_COOKIE_BYTES, PENDING_LIFETIME, ReturnTo, STEP_UP_RETURN, SessionCookie,
};
use crate::{
    Acr, AuthorizeRequest, CallbackParams, LoginError, RefreshToken, StepUpRequirement, TokenError,
    axum::{StoredLogin, seal::SealError, session::PendingAuthorization},
    protocol::{oauth::Scope, sdk::ErrorCategory},
};
use axum::{
    Form, Json,
    extract::{Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sourceorigin_common::ErrorChain;
use std::{sync::Arc, time::Duration};

/// Longest a session's revocation may hold up the sign-in or logout ending it,
/// whatever the HTTP client's own timeout.
const REVOCATION_DEADLINE: Duration = Duration::from_secs(5);

/// The query of `GET /login`.
#[derive(Deserialize)]
pub(super) struct StartQuery {
    /// Where to go once signed in.
    return_to: Option<String>,
    /// Longest acceptable time since the user authenticated, for step-up.
    max_age: Option<u32>,
    /// Required authentication context class, for step-up.
    acr_values: Option<String>,
    /// Whether the login steps up, even with no requirement to ask for, as a bare
    /// `insufficient_user_authentication` challenge leaves it (RFC 9470 §4).
    #[serde(default)]
    step_up: bool,
}

/// The form auth posts to `POST /backchannel-logout`.
#[derive(Deserialize)]
pub(super) struct LogoutForm {
    /// The signed logout token.
    logout_token: String,
}

impl Login {
    /// `GET /login`: keeps a pending login in a sealed cookie and redirects to auth.
    pub(super) async fn start(
        State(login): State<Arc<Self>>,
        headers: HeaderMap,
        Query(query): Query<StartQuery>,
    ) -> Response {
        let return_to = query
            .return_to
            .and_then(|path| path.parse().ok())
            .unwrap_or_else(|| login.home.clone());
        let step_up = StepUpRequirement {
            acr: query.acr_values.as_deref().and_then(Acr::select),
            max_age: query.max_age,
        };
        // Without a refresh token, a session could not learn that auth ended it.
        let mut scopes = login.scopes.clone();
        scopes.insert(Scope::OfflineAccess);
        let request = AuthorizeRequest {
            scopes,
            step_up,
            ..AuthorizeRequest::default()
        };
        let (url, pending) = match login.client.authorize(&request).await {
            Ok(started) => started,
            Err(LoginError::Randomness(_)) => {
                tracing::error!("operating system randomness is unavailable");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            // Auth refused or could not take the pushed request.
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), "sign-in could not start");
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Sign-in could not start: {error}."),
                )
                    .into_response();
            }
        };
        let name = login.cookies.pending(pending.state());
        // A step-up strengthens the session it starts from, so it is pinned to its
        // user. The session holds no raw ID token to send as `id_token_hint`, so auth
        // may let another account sign in; the callback refuses it.
        let subject = match login.open_session(&headers) {
            SessionCookie::Open(session) if query.step_up => Some(session.subject().to_owned()),
            _ => None,
        };
        let mut pending = PendingAuthorization {
            login: pending,
            return_to,
            step_up: query.step_up,
            subject,
            expires_at: login.now() + PENDING_LIFETIME,
        };
        // A `return_to` too long for the cookie returns home instead, or to the root
        // if home is too long too.
        let mut fallbacks = [login.home.clone(), ReturnTo::root()].into_iter();
        let sealed = loop {
            let sealed = match login.seal_pending(&pending, &name) {
                Ok(sealed) => sealed,
                Err(error) => return Self::failure(&error, "a pending login could not be sealed"),
            };
            if name.len() + sealed.len() <= MAX_PENDING_COOKIE_BYTES {
                break sealed;
            }
            let Some(fallback) = fallbacks.next() else {
                tracing::error!("even a login returning to the root outgrows its cookie");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            tracing::debug!("return_to is too long for the login cookie; falling back");
            pending.return_to = fallback;
        };
        let mut response = Redirect::to(url.as_str()).into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            Self::set_cookie(&name, &sealed, PENDING_LIFETIME),
        );
        response
    }

    /// `pending`, sealed for the cookie `name`.
    fn seal_pending(
        &self,
        pending: &PendingAuthorization,
        name: &str,
    ) -> Result<String, SealError> {
        self.cookie_key.pending.seal(pending, &self.context(name))
    }

    /// The pending login `sealed` holds as the cookie `name`, expired or not, if it
    /// opens: only then is the cookie this client's to read or drop.
    fn open_pending(&self, sealed: &str, name: &str) -> Option<PendingAuthorization> {
        self.cookie_key.pending.open(sealed, &self.context(name))
    }

    /// `GET /callback`: completes the pending login its `state` names and starts a
    /// session. Only the cookie holding that login is read and dropped, so a
    /// callback for another login, or a link with a made-up `state`, leaves logins in
    /// progress alone. Auth redeems a code once, so a copied cookie completes nothing
    /// twice.
    pub(super) async fn callback(
        State(login): State<Arc<Self>>,
        Query(callback): Query<CallbackParams>,
        headers: HeaderMap,
    ) -> Response {
        let state = callback.state.as_deref().unwrap_or_default();
        let name = login.cookies.pending(state);
        let pending = Self::cookie(&headers, &name)
            .and_then(|sealed| login.open_pending(sealed, &name))
            .filter(|pending| pending.login.state() == state);
        // A cookie that does not open, or holds another tab's login, is left alone.
        let Some(pending) = pending else {
            return (
                StatusCode::BAD_REQUEST,
                "This sign-in has no pending login; start again.",
            )
                .into_response();
        };
        let mut response = if pending.expires_at > login.now() {
            login.complete(&headers, pending, &callback).await
        } else {
            (
                StatusCode::BAD_REQUEST,
                "This sign-in expired; start again.",
            )
                .into_response()
        };
        // Spent whatever the outcome: the code may have been redeemed.
        response
            .headers_mut()
            .append(header::SET_COOKIE, Self::clear_cookie(&name));
        response
    }

    /// Completes `pending` from `callback` and starts its session. The session the
    /// browser had, in `headers`, is replaced, and its refresh token revoked before
    /// the new session is set, so no copy of it, nor a response still in flight that
    /// sets it back, outlives its access token. If auth cannot revoke it, the sign-in
    /// fails with 502 and the browser keeps its session; the code is spent, so the
    /// user starts again.
    ///
    /// A step-up must sign in the user it started from, and the one whose session it
    /// replaces, as after switching accounts in another tab: otherwise it fails, and
    /// the session it would replace is kept, its refresh token unrevoked.
    async fn complete(
        &self,
        headers: &HeaderMap,
        pending: PendingAuthorization,
        callback: &CallbackParams,
    ) -> Response {
        let tokens = match self.client.complete(pending.login, callback).await {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::debug!(error = %ErrorChain(&error), "sign-in failed");
                // The issuer's failures, unreachable or with unusable keys, are not the
                // browser's: answer 502, as the bearer path answers 503.
                let status = match error.code().code {
                    ErrorCategory::Network | ErrorCategory::Keys => StatusCode::BAD_GATEWAY,
                    _ => StatusCode::BAD_REQUEST,
                };
                return (status, format!("Sign-in failed: {error}.")).into_response();
            }
        };
        let Some(stored) = StoredLogin::new(tokens, self.now() + self.lifetime) else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        let previous = match self.open_session(headers) {
            SessionCookie::Open(previous) => Some(previous),
            _ => None,
        };
        let replaced = previous.as_ref().map(|previous| previous.subject());
        if pending.step_up
            && [pending.subject.as_deref(), replaced]
                .into_iter()
                .flatten()
                .any(|subject| subject != stored.subject())
        {
            tracing::debug!("a step-up signed in another account");
            self.abandon(&stored).await;
            return (
                StatusCode::BAD_REQUEST,
                "Sign-in failed: this step-up signed in another account than this session's.",
            )
                .into_response();
        }
        if let Some(refresh_token) = previous
            .as_ref()
            .and_then(|previous| previous.refresh_token())
            && !self.revoke(refresh_token).await
        {
            self.abandon(&stored).await;
            return (
                StatusCode::BAD_GATEWAY,
                "Signing in could not end your previous session; start again.",
            )
                .into_response();
        }
        let session = match self.session_cookie(&stored) {
            Ok(session) => session,
            Err(error) => {
                tracing::error!(error = %ErrorChain(&error), "sign-in failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Sign-in failed: {error}."),
                )
                    .into_response();
            }
        };
        let mut response = Redirect::to(pending.return_to.as_str()).into_response();
        let cookies = response.headers_mut();
        cookies.append(header::SET_COOKIE, session);
        // A step-up marks its return; any other sign-in drops an unused marker, which
        // belonged to the session this one replaces.
        let marker = if pending.step_up {
            Self::set_cookie(
                &self.cookies.step_up,
                &Self::step_up_marker(pending.return_to.as_str()),
                STEP_UP_RETURN,
            )
        } else {
            Self::clear_cookie(&self.cookies.step_up)
        };
        cookies.append(header::SET_COOKIE, marker);
        response
    }

    /// Revokes the grant of `login`, a sign-in the callback refuses after redeeming
    /// its code, so it does not live on at auth unused. A failure is logged by
    /// [`Self::revoke`] and changes nothing: the refusal stands either way.
    async fn abandon(&self, login: &StoredLogin) {
        if let Some(refresh_token) = login.refresh_token() {
            self.revoke(refresh_token).await;
        }
    }

    /// Revokes `refresh_token` at auth, within [`REVOCATION_DEADLINE`], so a hanging
    /// auth cannot hold up the sign-in or logout around it. Returns whether auth
    /// revoked it, logging why not.
    async fn revoke(&self, refresh_token: &RefreshToken) -> bool {
        match tokio::time::timeout(REVOCATION_DEADLINE, self.client.revoke(refresh_token)).await {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                tracing::warn!(error = %ErrorChain(&error), "a refresh token could not be revoked");
                false
            }
            Err(_) => {
                tracing::warn!("revoking a refresh token timed out");
                false
            }
        }
    }

    /// `POST /logout`: revokes the session's refresh token at auth, so no copy of the
    /// cookie refreshes again, clears the cookies, and redirects to RP-initiated
    /// logout. If auth cannot revoke it, the answer is 502 and the cookie is kept, so
    /// the user can try again: clearing it would leave copies refreshing. `POST`
    /// only, and only from the app's own pages, so another site cannot sign the user
    /// out.
    pub(super) async fn logout(State(login): State<Arc<Self>>, headers: HeaderMap) -> Response {
        if !login.same_origin(&headers) {
            return (
                StatusCode::FORBIDDEN,
                "Sign out from this site's own pages.",
            )
                .into_response();
        }
        let mut destination = login.home.as_str().to_owned();
        if let SessionCookie::Open(session) = login.open_session(&headers) {
            if let Some(refresh_token) = session.refresh_token()
                && !login.revoke(refresh_token).await
            {
                return (
                    StatusCode::BAD_GATEWAY,
                    "Signing out could not reach the sign-in service; try again.",
                )
                    .into_response();
            }
            destination = login
                .client
                .logout_redirect(login.after_logout.as_ref())
                .into();
        }
        let mut response = Redirect::to(&destination).into_response();
        for cookie in [&login.cookies.session, &login.cookies.step_up] {
            response
                .headers_mut()
                .append(header::SET_COOKIE, Self::clear_cookie(cookie));
        }
        response
    }

    /// `POST /backchannel-logout`: validates auth's logout token and hands it to the
    /// app's handler (OIDC Back-Channel Logout 1.0 §2.8). Auth posts it server to
    /// server, so there is no origin to check: the signed token is the authentication.
    pub(super) async fn backchannel_logout(
        State(login): State<Arc<Self>>,
        form: Result<Form<LogoutForm>, FormRejection>,
    ) -> Response {
        let mut response = login.receive_logout(form.ok()).await;
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    /// Applies the logout token in `form`, answering as
    /// [`LoginRoutes::on_backchannel_logout`](super::LoginRoutes::on_backchannel_logout)
    /// documents.
    async fn receive_logout(&self, form: Option<Form<LogoutForm>>) -> Response {
        let invalid = || {
            let body = Json(serde_json::json!({ "error": "invalid_request" }));
            (StatusCode::BAD_REQUEST, body).into_response()
        };
        // The route is mounted only with a handler.
        let Some(handler) = &self.on_logout else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(Form(form)) = form else {
            tracing::warn!("back-channel logout without a logout_token form field");
            return invalid();
        };
        let token = match self.client.logout_token(&form.logout_token).await {
            Ok(token) => token,
            Err(error @ TokenError::Keys(_)) => {
                tracing::warn!(error = %ErrorChain(&error), "back-channel logout could not be validated");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            Err(error) => {
                tracing::warn!(error = %ErrorChain(&error), "invalid back-channel logout token");
                return invalid();
            }
        };
        match handler(token).await {
            Ok(()) => StatusCode::OK.into_response(),
            Err(error) => Self::failure(error.as_ref(), "the back-channel logout handler failed"),
        }
    }
}
