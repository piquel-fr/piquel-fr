//! piquel.fr's own pages, which auth serves on its site listener: the homepage and
//! Piquel's policies. Every other path redirects to the same one on auth, so links
//! sent before the settings moved, such as security notices' and verification
//! links, still open their page. Auth's public listener serves the policies too,
//! at the same paths, so its pages link them on their own origin.
//!
//! The pages are static: no session, no form, no script. Their
//! Content-Security-Policy loads nothing but the stylesheet.

use crate::{assets::EmbeddedAssets, oidc::SERVICE_DOCUMENTATION, routes, security::ApiError};
use axum::{
    Router,
    http::{HeaderValue, Uri, header, uri::PathAndQuery},
    response::{IntoResponse, Redirect, Response},
    routing::{MethodRouter, get},
};
use piquel_common::config::Origin;
use piquel_ui::{Area, HomeLinks, Policy, Title};
use topcoat::{
    context::Cx,
    view::{ViewExt, view},
};

/// Every page's Content-Security-Policy: the stylesheet, on the page's own origin,
/// and nothing else.
const POLICY: &str = "default-src 'none'; style-src 'self'; frame-ancestors 'none'; \
                      base-uri 'none'; form-action 'none'";

/// piquel.fr's pages, linking auth's at its origin.
#[derive(Clone)]
pub(crate) struct SiteApplication {
    /// Auth's origin, where the homepage links and every other path redirects.
    auth: Origin,
}

/// One of piquel.fr's pages.
#[derive(Clone, Copy)]
enum Page {
    /// The homepage.
    Home,
    /// One of Piquel's policies.
    Policy(Policy),
}

impl SiteApplication {
    /// The site of the auth service at `auth`.
    pub(crate) fn new(auth: &Origin) -> Self {
        Self { auth: auth.clone() }
    }

    /// The policies alone, which auth's public listener serves too.
    pub(crate) fn policies(&self) -> Router {
        Policy::ALL
            .into_iter()
            .fold(Router::new(), |router, policy| {
                router.route(
                    routes::page::policy(policy),
                    self.page(Page::Policy(policy)),
                )
            })
    }

    /// Everything the site listener serves: the homepage, the policies and the
    /// stylesheet, and a temporary redirect of every other path, with its query,
    /// to auth, so browsers cache nothing should piquel.fr serve it later.
    pub(crate) fn routes(self) -> Router {
        let stylesheet = EmbeddedAssets::STYLESHEET.path();
        let auth = self.auth.serialized();
        self.policies()
            .route(routes::page::ROOT, self.page(Page::Home))
            .route(
                &stylesheet,
                get(|uri: Uri| std::future::ready(EmbeddedAssets::serve(uri.path()))),
            )
            .fallback(move |uri: Uri| {
                let path = uri.path_and_query().map_or("/", PathAndQuery::as_str);
                std::future::ready(Redirect::temporary(&format!("{auth}{path}")))
            })
    }

    /// The route showing `page`.
    fn page(&self, page: Page) -> MethodRouter {
        let site = self.clone();
        get(move || async move { site.render(page).await })
    }

    /// Answers with `page` in Piquel's document.
    async fn render(&self, page: Page) -> Result<Response, ApiError> {
        let cx = Cx::default();
        let stylesheet = EmbeddedAssets::STYLESHEET.path();
        let (sign_in, register, settings, developers) = (
            self.auth.join(routes::page::LOGIN),
            self.auth.join(routes::page::REGISTER),
            self.auth.join(routes::page::settings::HOME),
            self.auth.join(routes::page::developers::HOME),
        );
        let links = HomeLinks {
            sign_in: &sign_in,
            register: &register,
            settings: &settings,
            developers: &developers,
            documentation: SERVICE_DOCUMENTATION,
        };
        let title = match page {
            Page::Home => Title::Home,
            Page::Policy(policy) => policy.title(),
        };
        let html = view! { cx =>
            piquel_ui::document(
                title: title.as_str(),
                stylesheet: &stylesheet,
                home: routes::page::ROOT,
                area: Area::Site,
                policies: routes::page::POLICIES,
                match page {
                    Page::Home => piquel_ui::home(links: links),
                    Page::Policy(policy) => piquel_ui::policy(of: policy),
                }
            )
        }
        .single()
        .await
        .map_err(|error| ApiError::internal(&*error))?
        .render(&cx);
        Ok((
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(POLICY),
                ),
            ],
            html,
        )
            .into_response())
    }
}
