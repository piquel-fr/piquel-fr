use crate::config::AUTH_MOUNT;
use axum::{extract::FromRequestParts, response::IntoResponse};
use piquel_admin_api::{AdminClient, ApiError, CONFIRMATION_MAX_AGE};
use piquel_auth::{AuthenticationPolicy, StepUpRequirement, UserId, axum::SignedIn};
use std::{
    future::Future,
    sync::{Mutex, PoisonError},
};
use topcoat::{
    Error, Result,
    context::{Cx, app_context, memoize},
    router::{
        Body, Method, Next,
        content::Form,
        error::see_other,
        layer,
        request::{method, parts, uri},
        response::Response,
    },
};

/// How long an administrator has to fill in and submit a form, once shown: the
/// form asks for a confirmation this much newer than the API will need. It also
/// covers the SDK's 30-second clock leeway, which the API does not allow.
const FORM_TIME: u32 = 120;

/// What a form for the admin API's mutations needs: a passkey confirmation recent
/// enough that the API still accepts it when the form is submitted.
struct RecentPasskey;

impl AuthenticationPolicy for RecentPasskey {
    const REQUIREMENT: StepUpRequirement =
        StepUpRequirement::passkey_within(CONFIRMATION_MAX_AGE - FORM_TIME);
}

/// The SDK's answer in place of a page: a redirect through sign-in, or its
/// refusal once a step-up did not help. Pages fail with it, and [`sdk_responses`]
/// sends it, so the SDK's layer around the dashboard sees a step-up and redirects.
#[derive(Debug, thiserror::Error)]
#[error("the auth SDK answered for the page")]
struct SdkResponse(Mutex<Option<axum::response::Response>>);

impl SdkResponse {
    /// Fails the page with `response`.
    fn error(response: impl IntoResponse) -> Error {
        Self(Mutex::new(Some(response.into_response()))).into()
    }

    /// The response, the first time it is asked for.
    fn take(&self) -> Option<axum::response::Response> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// Answers a page that failed with an [`SdkResponse`] with that response.
#[layer("/")]
pub async fn sdk_responses(cx: &Cx, body: Body, next: Next<'_>) -> Result<Response> {
    let error = match next.run(cx, body).await {
        Ok(response) => return Ok(response),
        Err(error) => error,
    };
    match error
        .downcast_ref::<SdkResponse>()
        .and_then(SdkResponse::take)
    {
        Some(response) => Ok(response.map(Body::new)),
        None => Err(error),
    }
}

/// The signed-in administrator of a request, and the admin API they call.
pub struct Admin {
    /// The sign-in, whose access token the API accepts.
    user: SignedIn,
    /// The admin API.
    api: AdminClient,
}

impl Admin {
    /// The request's administrator. A browser without a session signs in first and
    /// comes back.
    pub async fn of(cx: &Cx) -> Result<&Self> {
        Self::load(cx).await.map_err(Error::clone)
    }

    /// Reads the administrator once per request, so the layout and the page share
    /// the session and any refresh of its access token.
    #[memoize(as_ref)]
    async fn load(cx: &Cx) -> Result<Self> {
        // The SDK's extractor reads the session the SDK's layer attached.
        let mut parts = parts(cx).clone();
        let user = SignedIn::from_request_parts(&mut parts, &())
            .await
            .map_err(SdkResponse::error)?;
        Ok(Self {
            user,
            api: app_context::<AdminClient>(cx).clone(),
        })
    }

    /// The administrator's name.
    pub fn name(&self) -> &str {
        self.user.name()
    }

    /// The administrator's account ID.
    pub fn id(&self) -> Option<UserId> {
        self.user.user_id().ok()
    }

    /// Requires a passkey confirmation recent enough for the API's mutations, before
    /// a page shows its form. A `GET` signs in again and comes back to the page; so
    /// does a form posted once the confirmation expired, which is then submitted
    /// again.
    pub fn confirm(&self, cx: &Cx) -> Result<()> {
        match self.user.require::<RecentPasskey>() {
            Ok(()) => Ok(()),
            Err(step_up) if method(cx) == Method::GET => Err(SdkResponse::error(step_up)),
            Err(_) => Err(Self::sign_in_again(cx, RecentPasskey::REQUIREMENT)),
        }
    }

    /// Sends a posted form through the SDK's login, signing in as `requirement`
    /// asks, and back to the form's page. The SDK's layer redirects only a `GET`'s
    /// step-up, since it cannot replay a form; the administrator submits it again.
    fn sign_in_again(cx: &Cx, requirement: StepUpRequirement) -> Error {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        let page = uri(cx).path_and_query().map_or("/", |page| page.as_str());
        query.append_pair("return_to", page);
        for (name, value) in requirement.authorize_params() {
            query.append_pair(name, &value);
        }
        query.append_pair("step_up", "true");
        see_other(format!("{AUTH_MOUNT}/login?{}", query.finish())).into()
    }

    /// Reads from the API. When the API asks for another sign-in, the browser signs
    /// in again and comes back; other failures fail the page.
    pub async fn read<'a, T, F, Fut>(&'a self, call: F) -> Result<T>
    where
        F: FnOnce(&'a AdminClient, &'a str) -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        match call(&self.api, self.user.login().access_token.expose()).await {
            Ok(value) => Ok(value),
            Err(ApiError::SignIn(requirement)) => {
                Err(SdkResponse::error(self.user.step_up(requirement)))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Makes the change a posted `form` asks for, with its input. Returns nothing
    /// for a `GET`, which only shows the form: a link, even with a query string,
    /// never changes anything. A refusal comes back as the message to show on the
    /// form. When the API asks for another sign-in, the browser goes back to the
    /// form's page, which steps up.
    pub async fn change<'a, I, T, F, Fut>(
        &'a self,
        cx: &Cx,
        form: Option<Form<I>>,
        call: F,
    ) -> Result<Option<Result<T, String>>>
    where
        F: FnOnce(&'a AdminClient, &'a str, I) -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        let Some(Form(input)) = form.filter(|_| method(cx) == Method::POST) else {
            return Ok(None);
        };
        match call(&self.api, self.user.login().access_token.expose(), input).await {
            Ok(value) => Ok(Some(Ok(value))),
            Err(ApiError::Refused { body, .. }) => Ok(Some(Err(body.error))),
            Err(ApiError::SignIn(requirement)) => Err(Self::sign_in_again(cx, requirement)),
            Err(error) => Err(error.into()),
        }
    }

    /// Like [`Self::change`], then goes to `done` once the change is made.
    pub async fn submit<'a, I, F, Fut>(
        &'a self,
        cx: &Cx,
        form: Option<Form<I>>,
        done: String,
        call: F,
    ) -> Result<Option<String>>
    where
        F: FnOnce(&'a AdminClient, &'a str, I) -> Fut,
        Fut: Future<Output = Result<(), ApiError>>,
    {
        match self.change(cx, form, call).await? {
            Some(Ok(())) => Err(see_other(done).into()),
            Some(Err(refusal)) => Ok(Some(refusal)),
            None => Ok(None),
        }
    }
}
