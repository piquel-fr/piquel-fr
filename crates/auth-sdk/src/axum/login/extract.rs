//! The session extractors handlers take, and the [`StepUp`] response asking for a
//! stronger or more recent sign-in.

use super::{Login, layer::StepUpRetry};
use crate::{
    AuthenticationPolicy, IdToken, StepUpRequirement, TokenError, UserId, axum::StoredLogin,
};
use axum::{
    Extension,
    extract::{FromRequestParts, OriginalUri},
    http::{Method, StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// The signed-in user. Without a session, a `GET` is redirected through login and
/// back; other methods get 401. Needs [`LoginRoutes::layer`](super::LoginRoutes::layer).
///
/// A request that is not `GET`, `HEAD`, `OPTIONS` or `TRACE` must come from the app's
/// own pages, or it gets 403 before the session is read: `Sec-Fetch-Site:
/// same-origin` when the browser sends it, and otherwise an `Origin` equal to the
/// redirect URI's. So handlers need no CSRF token. Take [`CrossOrigin<SignedIn>`]
/// for an endpoint other origins must call with the session cookie.
///
/// ```no_run
/// use piquel_auth::axum::SignedIn;
///
/// async fn home(user: SignedIn) -> String {
///     format!("Hello {}", user.name())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SignedIn {
    /// The stored login, its access token fresh.
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
        let claims = self.login.id_token.claims();
        claims
            .profile
            .name
            .as_deref()
            .or(claims.profile.preferred_username.as_deref())
            .unwrap_or(&claims.sub)
    }

    /// The user's account ID.
    ///
    /// # Errors
    /// [`TokenError::InvalidSubject`] if `sub` is not an account ID.
    pub fn user_id(&self) -> Result<UserId, TokenError> {
        self.login.id_token.user_id()
    }

    /// The ID token of the sign-in.
    #[must_use]
    pub const fn id_token(&self) -> &IdToken {
        &self.login.id_token
    }

    /// The stored login, with the access token to call APIs for the user.
    #[must_use]
    pub const fn login(&self) -> &StoredLogin {
        &self.login
    }

    /// Requires the sign-in to meet `P`, or returns the [`StepUp`] that sends the
    /// user through login again and back to the same page.
    ///
    /// ```no_run
    /// use piquel_auth::{AuthenticationPolicy, StepUpRequirement, axum::{SignedIn, StepUp}};
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
        let signed_in = &self.login.id_token;
        if signed_in
            .require_authentication(P::REQUIREMENT, self.checked_at)
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
    /// use piquel_auth::{axum::SignedIn, protocol::challenge::BearerChallenge};
    ///
    /// async fn settings(user: SignedIn) -> Response {
    ///     let http = reqwest::Client::new();
    ///     let Ok(answer) = http
    ///         .get("https://api.example.com/settings")
    ///         .bearer_auth(user.login().access_token.expose())
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
    ///         Some(challenge) if answer.status() == 401 => {
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

/// The signed-in user, if any. Never rejects, except with 500 when the session
/// backend fails or [`LoginRoutes::layer`](super::LoginRoutes::layer) is missing, and with 403 when a request
/// that is not a safe method comes from another origin, as for [`SignedIn`].
///
/// ```no_run
/// use piquel_auth::axum::MaybeSignedIn;
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
/// use piquel_auth::axum::{CrossOrigin, SignedIn};
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
        if parts.method != Method::GET {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
        let login = parts
            .extensions
            .get::<Arc<Login>>()
            .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        // A nested router strips its prefix from `uri`; the original keeps it.
        let uri = parts
            .extensions
            .get::<OriginalUri>()
            .map_or(&parts.uri, |original| &original.0);
        let return_to = uri
            .path_and_query()
            .and_then(|path| path.as_str().parse().ok());
        Err(Redirect::to(&login.login_url(return_to.as_ref(), None)).into_response())
    }
}

impl<St: Send + Sync> FromRequestParts<St> for CrossOrigin<MaybeSignedIn> {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &St) -> Result<Self, Response> {
        let Some(login) = parts.extensions.get::<Arc<Login>>() else {
            tracing::error!("SignedIn needs LoginRoutes::layer around the route");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        };
        let retry = parts.extensions.get::<StepUpRetry>().is_some();
        login
            .session(&parts.headers, retry)
            .await
            .map(|user| Self(MaybeSignedIn(user)))
            .map_err(|error| Login::store_failure(&error))
    }
}

/// A response asking the user to sign in again, more strongly or more recently, from
/// [`SignedIn::require`] or [`SignedIn::step_up`]. With [`LoginRoutes::layer`](super::LoginRoutes::layer) around
/// the route, a `GET` is redirected through login with `acr_values` and `max_age`,
/// and comes back to the same page; other requests get 401. The login fails unless
/// the new sign-in meets the requirement, and a step-up asked for again on the page's
/// return is [exhausted](Self::exhausted), so each action signs in again at most once,
/// as long as the browser returns within a minute ([`SignedIn::step_up`]).
///
/// ```no_run
/// use piquel_auth::{
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
