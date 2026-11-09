//! The session extractors handlers take, and the [`StepUp`] response asking for a
//! stronger or more recent sign-in.

use super::{Login, layer::RequestSession};
use crate::{
    AuthenticationPolicy, SessionId, StepUpRequirement, TokenError, UserId, axum::StoredLogin,
    protocol::claims::IdTokenClaims,
};
use axum::{
    Extension,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// The signed-in user. Without a session, a browser navigating to a page
/// (`Sec-Fetch-Mode: navigate`) is redirected through login and back; any other
/// request, a `fetch` included, gets 401, since a redirect to auth would fail its
/// CORS check. When the access token expired and auth could not
/// renew it, the request gets 503, and the session is kept for the next one. Needs [`LoginRoutes::layer`](super::LoginRoutes::layer).
///
/// A request that is not `GET`, `HEAD`, `OPTIONS` or `TRACE` must come from the app's
/// own pages, or it gets 403 before the session is read: `Sec-Fetch-Site:
/// same-origin` when the browser sends it, and otherwise an `Origin` equal to the
/// redirect URI's. So handlers need no CSRF token. Take [`CrossOrigin<SignedIn>`]
/// for an endpoint other origins must call with the session cookie.
///
/// ```no_run
/// use sourceorigin_auth::axum::SignedIn;
///
/// async fn home(user: SignedIn) -> String {
///     format!("Hello {}", user.name())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SignedIn {
    /// The session, its access token fresh.
    pub(super) login: StoredLogin,
    /// When the session was read, by the issuer's clock.
    pub(super) checked_at: DateTime<Utc>,
    /// Whether the request returns from a step-up login, so it is the retry.
    pub(super) retry: bool,
}

impl SignedIn {
    /// The user's name: the display name, else the username, else the account ID.
    #[must_use]
    pub fn name(&self) -> &str {
        let claims = self.claims();
        claims
            .profile
            .name
            .as_deref()
            .or(claims.profile.preferred_username.as_deref())
            .unwrap_or(&claims.sub)
    }

    /// The URL of the user's profile picture, a square JPEG, when the `profile`
    /// scope was granted and the account has one. The image at a URL never
    /// changes, so `<img>` tags and caches may keep it; a new picture comes with a
    /// new URL, at the next sign-in.
    #[must_use]
    pub fn picture(&self) -> Option<&str> {
        self.claims().profile.picture.as_deref()
    }

    /// The user's account ID.
    ///
    /// # Errors
    /// [`TokenError::InvalidSubject`] if `sub` is not an account ID.
    pub fn user_id(&self) -> Result<UserId, TokenError> {
        TokenError::account(self.subject())
    }

    /// The user's `sub`.
    #[must_use]
    pub fn subject(&self) -> &str {
        self.login.subject()
    }

    /// Auth's session ID, which a back-channel logout names.
    #[must_use]
    pub const fn sid(&self) -> Option<SessionId> {
        self.login.sid()
    }

    /// The validated claims of the sign-in's ID token, or of the latest refresh that
    /// returned one.
    #[must_use]
    pub const fn claims(&self) -> &IdTokenClaims {
        self.login.claims()
    }

    /// The session, with the access token to call APIs for the user.
    #[must_use]
    pub const fn login(&self) -> &StoredLogin {
        &self.login
    }

    /// Requires the sign-in to meet `P`, or returns the [`StepUp`] that sends the
    /// user through login again and back to the same page.
    ///
    /// ```no_run
    /// use sourceorigin_auth::{AuthenticationPolicy, StepUpRequirement, axum::{SignedIn, StepUp}};
    ///
    /// /// A sign-in within the last five minutes, however it was made.
    /// struct RecentLogin;
    ///
    /// impl AuthenticationPolicy for RecentLogin {
    ///     const REQUIREMENT: StepUpRequirement = StepUpRequirement {
    ///         acr: None,
    ///         max_age: Some(300),
    ///     };
    /// }
    ///
    /// async fn settings(user: SignedIn) -> Result<String, StepUp> {
    ///     user.require::<RecentLogin>()?;
    ///     Ok("settings".into())
    /// }
    /// ```
    ///
    /// # Errors
    /// The [`StepUp`] asking for `P`'s requirement.
    pub fn require<P: AuthenticationPolicy>(&self) -> Result<(), StepUp> {
        let authentication = &self.claims().authentication;
        if TokenError::require_authentication(
            P::REQUIREMENT,
            authentication.acr.as_ref(),
            authentication.auth_time,
            self.checked_at,
        )
        .is_ok()
        {
            Ok(())
        } else {
            Err(self.step_up(P::REQUIREMENT))
        }
    }

    /// Answers an API's `insufficient_user_authentication` challenge (RFC 9470) with
    /// the [`StepUp`] that signs the user in again as it asks, and comes back to the
    /// same page to call the API again. On that return the retry is spent: if the API
    /// still refuses, the step-up is [exhausted](StepUp::exhausted) and answers 403
    /// instead of redirecting again.
    ///
    /// The return is the first `GET` of that page within a minute of the login. A
    /// later return counts as a new action and may step up again, and another tab
    /// loading the same page in that minute uses up the retry instead.
    ///
    /// ```no_run
    /// use axum::response::{IntoResponse, Response};
    /// use sourceorigin_auth::{
    ///     axum::SignedIn,
    ///     protocol::challenge::{BearerChallenge, BearerError},
    /// };
    ///
    /// async fn settings(user: SignedIn) -> Response {
    ///     let http = reqwest::Client::new();
    ///     let Ok(answer) = http
    ///         .get("https://api.example.com/settings")
    ///         .bearer_auth(user.login().access_token().expose())
    ///         .send()
    ///         .await
    ///     else {
    ///         return "The API is unreachable.".into_response();
    ///     };
    ///     let challenge = answer
    ///         .headers()
    ///         .get(reqwest::header::WWW_AUTHENTICATE)
    ///         .and_then(|value| value.to_str().ok())
    ///         .and_then(|value| value.parse::<BearerChallenge>().ok());
    ///     match challenge {
    ///         // Only this error asks for a stronger sign-in: an `invalid_token`, for
    ///         // one, would not be cured by another.
    ///         Some(challenge)
    ///             if challenge.error == Some(BearerError::InsufficientUserAuthentication) =>
    ///         {
    ///             user.step_up(challenge.step_up).into_response()
    ///         }
    ///         _ => answer.text().await.unwrap_or_default().into_response(),
    ///     }
    /// }
    /// ```
    #[must_use]
    pub const fn step_up(&self, requirement: StepUpRequirement) -> StepUp {
        StepUp {
            requirement,
            exhausted: self.retry,
        }
    }
}

impl<St: Send + Sync> FromRequestParts<St> for SignedIn {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Response> {
        if let Some(refusal) = Login::refuse_other_origin(parts) {
            return Err(refusal);
        }
        let CrossOrigin(user) = CrossOrigin::<Self>::from_request_parts(parts, state).await?;
        Ok(user)
    }
}

/// The signed-in user, if any. Never rejects, except with 500 when
/// [`LoginRoutes::layer`](super::LoginRoutes::layer) is missing, with 403 when a
/// request that is not a safe method comes from another origin, and with 503 when
/// the access token expired and auth could not renew it, as for [`SignedIn`].
///
/// ```no_run
/// use sourceorigin_auth::axum::MaybeSignedIn;
///
/// async fn landing(MaybeSignedIn(user): MaybeSignedIn) -> String {
///     match user {
///         Some(user) => format!("Welcome back, {}", user.name()),
///         None => "Welcome! Sign in at /auth/login".into(),
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct MaybeSignedIn(pub Option<SignedIn>);

impl<St: Send + Sync> FromRequestParts<St> for MaybeSignedIn {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Response> {
        if let Some(refusal) = Login::refuse_other_origin(parts) {
            return Err(refusal);
        }
        let CrossOrigin(user) = CrossOrigin::<Self>::from_request_parts(parts, state).await?;
        Ok(user)
    }
}

/// [`SignedIn`] or [`MaybeSignedIn`] without the origin check, for an endpoint other
/// origins call with the session cookie, such as a sibling site's `fetch` with
/// credentials under CORS. The endpoint then guards against cross-site request
/// forgery itself.
///
/// ```no_run
/// use sourceorigin_auth::axum::{CrossOrigin, SignedIn};
///
/// async fn widget_vote(CrossOrigin(user): CrossOrigin<SignedIn>) -> String {
///     format!("Vote recorded for {}", user.name())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CrossOrigin<T>(pub T);

impl<St: Send + Sync> FromRequestParts<St> for CrossOrigin<SignedIn> {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Response> {
        let CrossOrigin(MaybeSignedIn(user)) =
            CrossOrigin::<MaybeSignedIn>::from_request_parts(parts, state).await?;
        if let Some(user) = user {
            return Ok(Self(user));
        }
        if !Login::navigation(&parts.method, &parts.headers) {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        let request = parts
            .extensions
            .get::<Arc<RequestSession>>()
            .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        let return_to = Login::requested(&parts.extensions, &parts.uri).parse().ok();
        Err(Redirect::to(&request.login.login_url(return_to.as_ref(), None)).into_response())
    }
}

impl<St: Send + Sync> FromRequestParts<St> for CrossOrigin<MaybeSignedIn> {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &St) -> Result<Self, Response> {
        let Some(request) = parts.extensions.get::<Arc<RequestSession>>() else {
            tracing::error!("SignedIn needs LoginRoutes::layer around the route");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        };
        request
            .user(&parts.headers)
            .await
            .map(|user| Self(MaybeSignedIn(user)))
            .map_err(IntoResponse::into_response)
    }
}

/// A response asking the user to sign in again, more strongly or more recently, from
/// [`SignedIn::require`] or [`SignedIn::step_up`]. With [`LoginRoutes::layer`](super::LoginRoutes::layer) around
/// the route, a browser navigating to a page is redirected through login with
/// `acr_values` and `max_age`, and comes back to the same page; other requests, a
/// `fetch` included, get 401. The login fails unless
/// the new sign-in meets the requirement, and a step-up asked for again on the page's
/// return is [exhausted](Self::exhausted), so each action signs in again at most once,
/// as long as the browser returns within a minute ([`SignedIn::step_up`]).
///
/// ```no_run
/// use sourceorigin_auth::{
///     AuthenticationPolicy, StepUpRequirement,
///     axum::{SignedIn, StepUp},
/// };
///
/// /// A passkey confirmation within the last five minutes.
/// struct RecentPasskey;
///
/// impl AuthenticationPolicy for RecentPasskey {
///     const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(300);
/// }
///
/// async fn delete_account(user: SignedIn) -> Result<&'static str, StepUp> {
///     user.require::<RecentPasskey>()?;
///     Ok("deleted")
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUp {
    /// What the new sign-in must meet.
    pub(super) requirement: StepUpRequirement,
    /// Whether this request already returns from a step-up, so another would not help.
    exhausted: bool,
}

impl StepUp {
    /// What the new sign-in must meet.
    #[must_use]
    pub const fn requirement(&self) -> StepUpRequirement {
        self.requirement
    }

    /// Whether the user already stepped up for this action and is still refused. An
    /// exhausted step-up answers 403 instead of redirecting.
    #[must_use]
    pub const fn exhausted(&self) -> bool {
        self.exhausted
    }
}

impl IntoResponse for StepUp {
    /// 401, marked for the layer to redirect; 403 once exhausted.
    fn into_response(self) -> Response {
        if self.exhausted {
            return (
                StatusCode::FORBIDDEN,
                "Signing in again did not give access to this page.",
            )
                .into_response();
        }
        (StatusCode::UNAUTHORIZED, Extension(self)).into_response()
    }
}
