//! The routes' handlers: starting a login, completing it, and both logouts.

use super::{
    Login, MAX_PENDING_BYTES, MAX_PENDING_COOKIE_BYTES, MAX_PENDING_LOGINS, PENDING_LIFETIME,
    STEP_UP_RETURN,
};
use crate::{
    Acr, AuthorizeRequest, CallbackParams, LoginError, StepUpRequirement, TokenError,
    axum::{
        StoredLogin,
        bearer::ErrorChain,
        seal::SealError,
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
use chrono::{DateTime, TimeDelta, Utc};
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
        let request = AuthorizeRequest {
            scopes: login.scopes.clone(),
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
        // The SDK's `state` is base64url, so it always names a cookie.
        let Some(name) = login.cookies.pending(pending.state()) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let now = login.now();
        let mut pending = PendingAuthorization {
            login: pending,
            return_to,
            step_up: query.step_up,
            expires_at: now + PENDING_LIFETIME,
        };
        let mut sealed = login.seal_pending(&pending, &name);
        if sealed
            .as_ref()
            .is_ok_and(|sealed| name.len() + sealed.len() > MAX_PENDING_COOKIE_BYTES)
        {
            tracing::debug!("return_to is too long for the login cookie; returning home");
            pending.return_to = login.home.clone();
            sealed = login.seal_pending(&pending, &name);
        }
        let sealed = match sealed {
            Ok(sealed) => sealed,
            Err(error) => {
                tracing::error!(error = %ErrorChain(&error), "a pending login could not be sealed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let mut response = Redirect::to(url.as_str()).into_response();
        let cookies = response.headers_mut();
        for stale in login.stale_logins(&headers, now, name.len() + sealed.len()) {
            cookies.append(
                header::SET_COOKIE,
                Self::set_cookie(stale, "", TimeDelta::zero()),
            );
        }
        cookies.append(
            header::SET_COOKIE,
            Self::set_cookie(&name, &sealed, PENDING_LIFETIME),
        );
        response
    }

    /// The associated data of the pending login cookie `name`: the client ID and the
    /// name, so a cookie opens only for the login its `state` names, and only for this
    /// client, even when another app on the host shares the cookie key and its
    /// cookies' names start like this app's.
    fn pending_context(&self, name: &str) -> String {
        format!("{}\0{name}", self.client.config().client_id)
    }

    /// `pending`, sealed for the cookie `name`.
    fn seal_pending(
        &self,
        pending: &PendingAuthorization,
        name: &str,
    ) -> Result<String, SealError> {
        self.cookie_key.0.seal(pending, &self.pending_context(name))
    }

    /// The pending login `sealed` holds as the cookie `name`, expired or not, if it
    /// opens: only then is the cookie this client's to read or drop.
    fn open_pending(&self, sealed: &str, name: &str) -> Option<PendingAuthorization> {
        self.cookie_key.0.open(sealed, &self.pending_context(name))
    }

    /// The pending login cookies a new login of `adding` bytes drops: this client's
    /// that expired, and the oldest beyond [`MAX_PENDING_LOGINS`] or
    /// [`MAX_PENDING_BYTES`]. A cookie that does not open is not this client's, or
    /// was sealed under an older key, and is left to its `Max-Age`.
    fn stale_logins<'a>(
        &self,
        headers: &'a HeaderMap,
        now: DateTime<Utc>,
        adding: usize,
    ) -> Vec<&'a str> {
        let (mut live, mut stale) = (Vec::new(), Vec::new());
        for (name, sealed) in Self::cookies(headers) {
            if !name.starts_with(&self.cookies.pending) {
                continue;
            }
            match self.open_pending(sealed, name) {
                Some(pending) if pending.expires_at > now => {
                    live.push((pending.expires_at, name, name.len() + sealed.len()));
                }
                Some(_) => stale.push(name),
                None => {}
            }
        }
        // Newest first, keeping each while it fits.
        live.sort_unstable_by_key(|&(expires_at, _, _)| std::cmp::Reverse(expires_at));
        let (mut count, mut bytes) = (1, adding);
        for (_, name, size) in live {
            if count < MAX_PENDING_LOGINS && bytes + size <= MAX_PENDING_BYTES {
                count += 1;
                bytes += size;
            } else {
                stale.push(name);
            }
        }
        stale
    }

    /// `GET /callback`: completes the pending login its `state` names and starts a
    /// session. Only that login's cookie is read and dropped, so a callback for
    /// another login, or a link with a made-up `state`, leaves logins in progress
    /// alone. Auth redeems a code once, so a copied cookie completes nothing twice.
    pub(super) async fn callback(
        State(login): State<Arc<Self>>,
        headers: HeaderMap,
        Query(callback): Query<CallbackParams>,
    ) -> Response {
        let name = callback
            .state
            .as_deref()
            .and_then(|state| login.cookies.pending(state));
        let pending = name.as_deref().and_then(|name| {
            let sealed = Self::cookie(&headers, name)?;
            login.open_pending(sealed, name)
        });
        // A cookie that does not open, perhaps another app's, is left alone.
        let (Some(name), Some(pending)) = (name, pending) else {
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
        response.headers_mut().append(
            header::SET_COOKIE,
            Self::set_cookie(&name, "", TimeDelta::zero()),
        );
        response
    }

    /// Completes `pending` from `callback` and starts its session.
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
                let status = if error.code().code == crate::protocol::sdk::ErrorCategory::Network {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::BAD_REQUEST
                };
                return (status, format!("Sign-in failed: {error}.")).into_response();
            }
        };
        let issuer = self.client.issuer().issuer().to_owned();
        let (Some(stored), Ok(session)) =
            (StoredLogin::new(issuer, tokens), SessionKey::generate())
        else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        // A fresh key on every sign-in: a key planted before login is worthless after.
        if let Some(previous) =
            Self::cookie(headers, &self.cookies.session).and_then(SessionKey::parse)
            && let Err(error) = self.sessions.delete(&previous).await
        {
            return Self::store_failure(&error);
        }
        let now = self.now();
        match self
            .sessions
            .insert(&session, &stored, now + self.lifetime, now)
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
            Self::set_cookie(&self.cookies.session, session.as_cookie(), self.lifetime),
        );
        // A step-up marks its return; any other sign-in drops an unused marker, which
        // belonged to the session this one replaces.
        let marker = if pending.step_up {
            Self::set_cookie(
                &self.cookies.step_up,
                &URL_SAFE_NO_PAD.encode(pending.return_to.as_str()),
                STEP_UP_RETURN,
            )
        } else {
            Self::set_cookie(&self.cookies.step_up, "", TimeDelta::zero())
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
        if let Some(key) =
            Self::cookie(&headers, &login.cookies.session).and_then(SessionKey::parse)
        {
            match login.sessions.load(&key, login.now()).await {
                Ok(Some(session)) => {
                    destination = login
                        .client
                        .logout_url(session.login.id_token(), login.after_logout.as_ref())
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
        for cookie in [&login.cookies.session, &login.cookies.step_up] {
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
