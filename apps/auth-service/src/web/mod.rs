//! auth.piquel.fr's server-rendered pages, grouped by area: the sign-in flows
//! (`auth`), the account settings (`settings`) and the developer console
//! (`developers`). Each handler resolves who acts, calls the service in-process
//! and renders `piquel-ui` components.
//!
//! A page answers `GET` with itself and `POST` with its form's result, at the route
//! [`routes::page`] declares. Axum mounts the Topcoat router on exactly those routes
//! and their trailing-slash twins, which Topcoat redirects to the page, never as the
//! fallback, so the security layer classifies them as pages by their route: it
//! attaches the request context, spends the pages' own rate budget, and accepts a
//! form only from auth's own pages. Every page's Content-Security-Policy loads
//! nothing but the stylesheet and the passkey script, and lets its forms post only
//! to auth and to where they redirect.

/// A page's entry in [`WebApplication::pages`]: its path, and the handlers showing it
/// and taking its form, whose failures explain themselves as the page `title`.
macro_rules! page {
    ($path:expr, $title:expr, $show:expr, $submit:expr $(,)?) => {
        (
            $path,
            |cx, _| Box::pin(Self::answer(cx, $title, $show(cx))),
            |cx, body| Box::pin(Self::answer(cx, $title, $submit(cx, body))),
        )
    };
}

/// The signed-in account's pages: their frame, and how each shows itself and makes
/// its changes.
mod account;
/// auth.piquel.fr's sign-in flows.
mod auth;
/// The developer console.
mod developers;
/// The account's settings.
mod settings;
#[cfg(test)]
mod tests;

use crate::{
    AuthConfig, MAX_REQUEST_BODY_BYTES,
    account::AccountService,
    assets::EmbeddedAssets,
    config::EmailConfig,
    federation::FederationApplication,
    oidc::{OAuthCode, OAuthError, OidcApplication, Reject},
    routes,
    security::{ApiError, RequestContext},
};
use auth::SignInPage;
use piquel_common::config::Origin;
use piquel_repository::Database;
use piquel_ui::{Area, Onward, QueryError, Title};
use serde::de::DeserializeOwned;
use std::{fmt, sync::Arc};
use topcoat::{
    Error, Result,
    context::Cx,
    router::{
        Body, BodyLimit, HeaderValue, Method, OriginPolicy, RouteFn, RouteHandlerFn, Router,
        StatusCode,
        content::Form,
        error::see_other,
        header, parse_query_params,
        request::{FromRequest, extensions},
        response::{IntoResponse, Response},
        tower::TowerService,
    },
    view::{Child, View, ViewExt, view},
};
use url::{Host, Url};

/// The pages, and what every one of them needs.
#[derive(Clone)]
pub(crate) struct WebApplication {
    /// The account the sign-in pages link to, and the settings pages and the
    /// developer console read and change.
    account: AccountService,
    /// The OAuth provider whose authorizations the sign-in pages continue, and whose
    /// consent and logout the pages complete.
    oidc: OidcApplication,
    /// Social sign-in, which the sign-in pages start and the settings link and list.
    federation: FederationApplication,
    /// Whether creating an account needs an invitation.
    invite_required: bool,
    /// Whether email is sent, which adding an address needs.
    email: EmailConfig,
    /// The `OpenID` Connect issuer, which the console tells apps to discover.
    issuer: Origin,
    /// Every page's Content-Security-Policy but its `form-action`.
    policy: Arc<str>,
}

/// What a page answers when it cannot show itself.
enum Failure {
    /// The request or its flow failed: the page explains `error`, with a `link`
    /// onwards as its label and URL.
    Explained {
        /// What failed.
        error: OAuthError,
        /// Where the user may go on from here.
        link: Option<(&'static str, String)>,
    },
    /// The account has no app by the ID the page's path names: another account's,
    /// a deleted one or none. The account page rendering says so, at `404`, below
    /// the account's bar; no other page names an app.
    Missing,
    /// Rendering or another internal step failed. It is logged, and Topcoat answers
    /// `500`.
    Internal(Error),
}

/// Why a page's form could not be read, keeping Topcoat's error as the cause of the
/// rejection, which needs a standard error.
#[derive(Debug)]
struct UnreadableForm(Error);

impl fmt::Display for UnreadableForm {
    /// Names the failure; the cause follows in the chain.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the form could not be read")
    }
}

impl std::error::Error for UnreadableForm {
    /// Topcoat's error.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

impl From<OAuthError> for Failure {
    /// Explains `error` with no link onwards.
    fn from(error: OAuthError) -> Self {
        Self::Explained { error, link: None }
    }
}

impl From<Error> for Failure {
    /// An internal failure.
    fn from(error: Error) -> Self {
        Self::Internal(error)
    }
}

impl From<QueryError> for Failure {
    /// An internal failure: a page's link could not be written.
    fn from(error: QueryError) -> Self {
        Self::Internal(error.into())
    }
}

impl WebApplication {
    /// Builds the pages over `database`, completing the flows of `oidc` and linking
    /// through `federation`, as `config` sets them up.
    pub(crate) fn new(
        database: Database,
        config: &AuthConfig,
        oidc: OidcApplication,
        federation: FederationApplication,
    ) -> Self {
        let origin = &config.oidc.origin;
        // A source with a path needs the whole URL: `'self'` names none. The passkey
        // script's ceremonies fetch auth's own JSON routes.
        let policy = format!(
            "default-src 'none'; style-src {}; script-src {}; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
            origin.join(&EmbeddedAssets::STYLESHEET.path()),
            origin.join(&EmbeddedAssets::SCRIPT.path()),
        );
        Self {
            account: AccountService::new(database),
            oidc,
            federation,
            invite_required: config.passkey.invite_required,
            email: config.email.clone(),
            issuer: origin.clone(),
            policy: policy.into(),
        }
    }

    /// Each page's route, the handler showing it and the one submitting its form.
    fn pages() -> [(&'static str, RouteHandlerFn, RouteHandlerFn); 17] {
        use routes::page::{
            CONSENT, LOGIN, LOGOUT, RECOVER, RECOVER_UNDO, REGISTER, settings::VERIFY,
        };
        [
            page!(
                LOGIN,
                SignInPage::Login.title(),
                |cx| Self::sign_in(cx, SignInPage::Login),
                |cx, body| Self::sign_in_change(cx, SignInPage::Login, body),
            ),
            page!(
                REGISTER,
                SignInPage::Register.title(),
                |cx| Self::sign_in(cx, SignInPage::Register),
                |cx, body| Self::sign_in_change(cx, SignInPage::Register, body),
            ),
            page!(
                CONSENT,
                Title::Consent.as_str(),
                Self::consent,
                Self::decide
            ),
            page!(
                LOGOUT,
                Title::Logout.as_str(),
                Self::logout,
                Self::end_session
            ),
            Self::entry::<settings::SignInMethods>(),
            Self::entry::<settings::Addresses>(),
            page!(
                VERIFY,
                Title::VerifyEmail.as_str(),
                Self::verify,
                Self::confirm_address,
            ),
            Self::entry::<settings::Devices>(),
            Self::entry::<settings::ConnectedApps>(),
            Self::entry::<settings::History>(),
            Self::entry::<developers::Apps>(),
            Self::entry::<developers::NewApp>(),
            Self::entry::<developers::Overview>(),
            Self::entry::<developers::AppSettings>(),
            Self::entry::<developers::AppSecrets>(),
            page!(
                RECOVER,
                Title::Recover.as_str(),
                Self::recover,
                Self::recover_change,
            ),
            page!(
                RECOVER_UNDO,
                Title::UndoRecovery.as_str(),
                Self::undo_recovery,
                Self::undo_recovery_change,
            ),
        ]
    }

    /// One Topcoat router serving every page, mounted on each page's route and its
    /// trailing-slash twin, and the redirect of auth's root to the settings.
    pub(crate) fn routes(self) -> axum::Router {
        let mut pages = Router::builder()
            .app_context(self)
            // The security layer already accepts forms only from auth's own pages, by a
            // stricter rule: Topcoat's also takes `Sec-Fetch-Site: none`.
            .origin_policy(OriginPolicy::dangerous_disable())
            // axum's body limit does not reach Topcoat, whose own default is 2 MiB.
            .layer(BodyLimit::max(MAX_REQUEST_BODY_BYTES));
        for (path, show, submit) in Self::pages() {
            pages = pages
                .route(RouteFn::new(Method::GET, path, show))
                .route(RouteFn::new(Method::POST, path, submit));
        }
        let service = TowerService::new(pages.build());
        Self::pages()
            .into_iter()
            .fold(axum::Router::new(), |router, (path, ..)| {
                router
                    .route_service(path, service.clone())
                    // Links ending in a slash, which piquel.fr's settings accepted, go on
                    // to the page: Topcoat answers them with a `308` to its own path,
                    // the query kept.
                    .route_service(&format!("{path}/"), service.clone())
            })
            .route(routes::page::ROOT, axum::routing::get(Self::root))
    }

    /// Sends auth's root on to the account's settings, which show the account or
    /// offer to sign in. Temporary, so browsers cache nothing should the root change.
    fn root() -> std::future::Ready<axum::response::Redirect> {
        std::future::ready(axum::response::Redirect::temporary(
            routes::page::settings::HOME,
        ))
    }

    /// Runs the handler `page` of the page titled `title`: its failure becomes the
    /// page explaining it, and internal failures are logged, since Topcoat logs none
    /// of the `500`s it answers for them.
    async fn answer(
        cx: &Cx,
        title: &str,
        page: impl Future<Output = std::result::Result<Response, Failure>>,
    ) -> Result<Response> {
        let web = topcoat::context::app_context::<Self>(cx);
        let answer = match page.await {
            Ok(response) => Ok(response),
            Err(Failure::Explained { error, link }) => {
                let link = link.as_ref().map(|(label, url)| (*label, url.as_str()));
                web.failure(cx, title, &error, link).await
            }
            Err(Failure::Missing) => Err(Error::msg(
                "a page that is not the account's named a missing app",
            )),
            Err(Failure::Internal(error)) => Err(error),
        };
        answer.inspect_err(|error| ApiError::log_error(&**error))
    }

    /// The context the security layer attached to the request.
    fn context(cx: &Cx) -> std::result::Result<RequestContext, Failure> {
        Ok(RequestContext::of(extensions(cx)).map_err(Error::from)?)
    }

    /// The page's query, as `T`. A malformed one is the request's fault.
    fn query<T: DeserializeOwned>(cx: &Cx) -> std::result::Result<T, OAuthError> {
        parse_query_params(cx).map_err(|error| {
            OAuthCode::InvalidRequest
                .reject_with(format!("the request is malformed: {error}"), error)
        })
    }

    /// The form posted to the page, as `T`. A malformed one is the request's fault.
    async fn form<T: DeserializeOwned + Send>(
        cx: &Cx,
        body: Body,
    ) -> std::result::Result<T, OAuthError> {
        let Form(form) = Form::from_request(cx, body).await.map_err(|error| {
            OAuthCode::InvalidRequest.reject_with(
                format!("the form is malformed: {error}"),
                UnreadableForm(error),
            )
        })?;
        Ok(form)
    }

    /// The Content-Security-Policy source naming `target`'s origin, or `None` when no
    /// policy can name it. Host sources name domains whose labels are letters,
    /// digits and hyphens, and never match an IP address (CSP3 §6.7.2.6), such as a
    /// native application's loopback callback (RFC 8252 §7.3).
    fn source(target: &Url) -> Option<String> {
        let nameable = match target.host() {
            Some(Host::Domain(domain)) => domain.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }),
            Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => false,
        };
        let origin = target.origin();
        (nameable && origin.is_tuple()).then(|| origin.ascii_serialization())
    }

    /// Sends the browser on to `target` once a form is done: a `303`, or, when the
    /// page's `form-action` could not name `target`, a page linking there, since the
    /// browser would block the form's redirect.
    async fn onward(&self, cx: &Cx, title: &str, target: &Url) -> Result<Response> {
        if Self::source(target).is_some() {
            return see_other(target).into_response(cx);
        }
        self.link(cx, title, target, Onward::Application).await
    }

    /// The page titled `title` linking to `target`, which leads `to` there. Following
    /// a link submits no form, so no `form-action` governs where it redirects.
    async fn link(&self, cx: &Cx, title: &str, target: &Url, to: Onward) -> Result<Response> {
        let page = view! { cx => piquel_ui::onward(href: target.as_str(), to: to) };
        self.render(cx, StatusCode::OK, title, Area::SignIn, &[], page)
            .await
    }

    /// Answers with `page` inside the document titled `title`, in `area`, under the
    /// page policy. The brand links the account's settings. Its forms may post to
    /// auth's own pages, and redirect on to the origins of `targets`: browsers apply
    /// `form-action` to a form's redirects too.
    async fn render(
        &self,
        cx: &Cx,
        status: StatusCode,
        title: &str,
        area: Area,
        targets: &[Url],
        page: impl View,
    ) -> Result<Response> {
        let page = Child::new(page);
        let (stylesheet, script) = (
            EmbeddedAssets::STYLESHEET.path(),
            EmbeddedAssets::SCRIPT.path(),
        );
        let html = view! { cx =>
            piquel_ui::document(
                title: title,
                stylesheet: &stylesheet,
                script: &script,
                home: routes::page::settings::HOME,
                area: area,
                (page)
            )
        }
        .single()
        .await?
        .render(cx);
        let mut form_action = "'self'".to_owned();
        for source in targets.iter().filter_map(Self::source) {
            form_action.push(' ');
            form_action.push_str(&source);
        }
        let policy = format!("{}; form-action {form_action}", self.policy);
        (
            status,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::try_from(policy)?,
                ),
            ],
            html,
        )
            .into_response(cx)
    }

    /// Answers with why the page titled `title` cannot go on: what `error`'s code
    /// means, at its status, its description when the request is at fault, and a
    /// `link` onwards as its label and URL.
    async fn failure(
        &self,
        cx: &Cx,
        title: &str,
        error: &OAuthError,
        link: Option<(&str, &str)>,
    ) -> Result<Response> {
        let (status, code, description) = error.public();
        let description = status.is_client_error().then_some(description);
        let page =
            view! { cx => piquel_ui::failure(code: &code, description: description, link: link) };
        self.render(cx, status, title, Area::SignIn, &[], page)
            .await
    }
}
