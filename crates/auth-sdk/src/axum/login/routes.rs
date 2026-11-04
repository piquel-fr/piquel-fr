//! The routes' handlers: starting a login, completing it, and both logouts.

use super::{
    LOGIN_COOKIE, Login, PENDING_LIFETIME, SESSION_COOKIE, STEP_UP_COOKIE, STEP_UP_RETURN,
};
use crate::{
    Acr, AuthorizeRequest, CallbackParams, LoginError, StepUpRequirement, TokenError,
    axum::{
        StoredLogin,
        bearer::ErrorChain,
        session::{PendingAuthorization, SessionKey},
    },
};
use axum::{
    Form, Json,
    extract::{Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::TimeDelta;
use serde::Deserialize;
use std::sync::Arc;

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
    /// `GET /login`: stores a pending login and redirects to auth.
    pub(super) async fn start(
        State(login): State<Arc<Self>>,
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
        let request = AuthorizeRequest {
            scopes: login.scopes.clone(),
            step_up,
            ..AuthorizeRequest::default()
        };
        let randomness_unavailable = || {
            tracing::error!("operating system randomness is unavailable");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        };
        let Ok(key) = SessionKey::generate() else {
            return randomness_unavailable();
        };
        let (url, pending) = match login.client.authorize(&request).await {
            Ok(started) => started,
            Err(LoginError::Randomness(_)) => return randomness_unavailable(),
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
        let pending = PendingAuthorization {
            login: pending,
            return_to,
            step_up: query.step_up,
        };
        let expires = login.now() + PENDING_LIFETIME;
        if let Err(error) = login.sessions.insert_pending(&key, &pending, expires).await {
            return Self::store_failure(&error);
        }
        let mut response = Redirect::to(url.as_str()).into_response();
        response.headers_mut().append(
            header::SET_COOKIE,
            Self::set_cookie(LOGIN_COOKIE, key.as_cookie(), PENDING_LIFETIME),
        );
        response
    }

    /// `GET /callback`: completes the pending login and starts a session.
    pub(super) async fn callback(
        State(login): State<Arc<Self>>,
        headers: HeaderMap,
        Query(callback): Query<CallbackParams>,
    ) -> Response {
        let Some(key) = Self::cookie(&headers, LOGIN_COOKIE).and_then(SessionKey::parse) else {
            return (
                StatusCode::BAD_REQUEST,
                "This sign-in has no pending login; start again.",
            )
                .into_response();
        };
        let pending = match login.sessions.take_pending(&key, login.now()).await {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "This sign-in expired or was already used; start again.",
                )
                    .into_response();
            }
            Err(error) => return Self::store_failure(&error),
        };
        let tokens = match login.client.complete(pending.login, &callback).await {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::debug!(error = %ErrorChain(&error), "sign-in failed");
                let status = if error.code().code == crate::protocol::sdk::ErrorCategory::Network {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::BAD_REQUEST
                };
                return (status, format!("Sign-in failed: {error}.")).into_response();
            }
        };
        let issuer = login.client.issuer().issuer().to_owned();
        let (Some(stored), Ok(session)) =
            (StoredLogin::new(issuer, tokens), SessionKey::generate())
        else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        // A fresh key on every sign-in: a key planted before login is worthless after.
        if let Some(previous) = Self::cookie(&headers, SESSION_COOKIE).and_then(SessionKey::parse)
            && let Err(error) = login.sessions.delete(&previous).await
        {
            return Self::store_failure(&error);
        }
        let now = login.now();
        match login
            .sessions
            .insert(&session, &stored, now + login.lifetime, now)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!("sign-in completed after auth ended its session");
                return (
                    StatusCode::BAD_REQUEST,
                    "Sign-in failed: this session was signed out; start again.",
                )
                    .into_response();
            }
            Err(error) => return Self::store_failure(&error),
        }
        let mut response = Redirect::to(pending.return_to.as_str()).into_response();
        let cookies = response.headers_mut();
        cookies.append(
            header::SET_COOKIE,
            Self::set_cookie(SESSION_COOKIE, session.as_cookie(), login.lifetime),
        );
        cookies.append(
            header::SET_COOKIE,
            Self::set_cookie(LOGIN_COOKIE, "", TimeDelta::zero()),
        );
        // A step-up marks its return; any other sign-in drops an unused marker, which
        // belonged to the session this one replaces.
        let marker = if pending.step_up {
            Self::set_cookie(
                STEP_UP_COOKIE,
                &URL_SAFE_NO_PAD.encode(pending.return_to.as_str()),
                STEP_UP_RETURN,
            )
        } else {
            Self::set_cookie(STEP_UP_COOKIE, "", TimeDelta::zero())
        };
        cookies.append(header::SET_COOKIE, marker);
        response
    }
    /// `POST /logout`: deletes the session and redirects to RP-initiated logout.
    /// `POST` only, and only from the app's own pages, so another site cannot sign
    /// the user out.
    pub(super) async fn logout(State(login): State<Arc<Self>>, headers: HeaderMap) -> Response {
        if !login.same_origin(&headers) {
            return (
                StatusCode::FORBIDDEN,
                "Sign out from this site's own pages.",
            )
                .into_response();
        }
        let mut destination = login.home.as_str().to_owned();
        if let Some(key) = Self::cookie(&headers, SESSION_COOKIE).and_then(SessionKey::parse) {
            match login.sessions.load(&key, login.now()).await {
                Ok(Some(session)) => {
                    destination = login
                        .client
                        .logout_url(&session.login.id_token, login.after_logout.as_ref())
                        .into();
                }
                Ok(None) => {}
                Err(error) => return Self::store_failure(&error),
            }
            if let Err(error) = login.sessions.delete(&key).await {
                return Self::store_failure(&error);
            }
        }
        let mut response = Redirect::to(&destination).into_response();
        for cookie in [SESSION_COOKIE, STEP_UP_COOKIE] {
            response.headers_mut().append(
                header::SET_COOKIE,
                Self::set_cookie(cookie, "", TimeDelta::zero()),
            );
        }
        response
    }

    /// `POST /backchannel-logout`: validates auth's logout token and deletes the
    /// sessions it names (OIDC Back-Channel Logout 1.0 §2.8). Auth posts it server to
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

    /// Applies the logout token in `form`, answering as [`LoginRoutes`](super::LoginRoutes) documents.
    async fn receive_logout(&self, form: Option<Form<LogoutForm>>) -> Response {
        let invalid = || {
            let body = Json(serde_json::json!({ "error": "invalid_request" }));
            (StatusCode::BAD_REQUEST, body).into_response()
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
        // An ended `sid` is remembered for as long as a session started now would
        // last, far beyond any ID token a racing sign-in could still complete with.
        let now = self.now();
        match self
            .sessions
            .log_out(&token, now + self.lifetime, now)
            .await
        {
            Ok(applied) => {
                if !applied {
                    tracing::debug!("back-channel logout token applied before");
                }
                StatusCode::OK.into_response()
            }
            Err(error) => Self::store_failure(&error),
        }
    }
}
