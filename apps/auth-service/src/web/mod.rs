//! auth.piquel.fr's server-rendered pages. Each handler resolves who acts, calls the
//! service in-process and renders `piquel-ui` components.
//!
//! A page answers `GET` with itself and `POST` with its form's result, at the path
//! [`routes::page`] declares. Axum mounts the Topcoat router on exactly those paths,
//! never as the fallback, so the security layer classifies them as pages: it attaches
//! the request context, spends the pages' own rate budget, and accepts a form only
//! from auth's own pages. Every page's Content-Security-Policy loads nothing but the
//! stylesheet and the SDK's script, and lets its forms post only to auth and to where
//! they redirect.

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

/// The consent page and the confirmation of an application's logout request.
mod oidc;
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
use piquel_repository::Database;
use piquel_ui::{Area, Title};
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
    /// The account settings the settings pages read and change.
    account: AccountService,
    /// The OAuth provider whose consent and logout the pages complete.
    oidc: OidcApplication,
    /// Social sign-in, which the settings link and list.
    federation: FederationApplication,
    /// Whether email is sent, which adding an address needs.
    email: EmailConfig,
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
        // A source with a path needs the whole URL: `'self'` names none. The SDK's
        // passkey ceremonies fetch auth's own JSON routes.
        let script =
            EmbeddedAssets::SCRIPT.map_or_else(|| "'none'".to_owned(), |path| origin.join(path));
        let policy = format!(
            "default-src 'none'; style-src {}; script-src {script}; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
            origin.join(EmbeddedAssets::STYLESHEET),
        );
        Self {
            account: AccountService::new(database),
            oidc,
            federation,
            email: config.email.clone(),
            policy: policy.into(),
        }
    }

    /// Each page's path, the handler showing it and the one submitting its form.
    fn pages() -> [(&'static str, RouteHandlerFn, RouteHandlerFn); 7] {
        use routes::page::{CONSENT, LOGOUT, settings::VERIFY};
        [
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
            Self::settings::<settings::SignInMethods>(),
            Self::settings::<settings::Addresses>(),
            page!(
                VERIFY,
                Title::VerifyEmail.as_str(),
                Self::verify,
                Self::confirm_address,
            ),
            Self::settings::<settings::Devices>(),
            Self::settings::<settings::History>(),
        ]
    }

    /// One Topcoat router serving every page, mounted on each page's path.
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
                router.route_service(path, service.clone())
            })
    }

    /// Runs the handler `page` of the page titled `title`: its failure becomes the
    /// page explaining it, and internal failures are logged, since Topcoat logs none
    /// of the `500`s it answers for them.
    async fn answer(
        cx: &Cx,
        title: &str,
        page: impl Future<Output = std::result::Result<Response, Failure>>,
    ) -> Result<Response> {
        let answer = match page.await {
            Ok(response) => Ok(response),
            Err(Failure::Explained { error, link }) => {
                let web = topcoat::context::app_context::<Self>(cx);
                let link = link.as_ref().map(|(label, url)| (*label, url.as_str()));
                web.failure(cx, title, &error, link).await
            }
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
        let page = view! { cx => piquel_ui::onward(href: target.as_str()) };
        self.render(cx, StatusCode::OK, title, Area::SignIn, &[], page)
            .await
    }

    /// Answers with `page` inside the document titled `title`, in `area`, under the
    /// page policy. Its forms may post to auth's own pages, and redirect on to the
    /// origins of `targets`: browsers apply `form-action` to a form's redirects too.
    async fn render(
        &self,
        cx: &Cx,
        status: StatusCode,
        title: &str,
        area: Area,
        targets: &[Url],
        page: impl View,
    ) -> Result<Response> {
        // The brand links the account's settings from its own pages.
        let home = match area {
            Area::Account => routes::page::settings::HOME,
            Area::SignIn => "/",
        };
        let page = Child::new(page);
        let html = view! { cx =>
            piquel_ui::document(
                title: title,
                stylesheet: EmbeddedAssets::STYLESHEET,
                script: EmbeddedAssets::SCRIPT,
                home: home,
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
