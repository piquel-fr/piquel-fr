//! The router: piquel.fr's pages, the shared stylesheet and typefaces, and a
//! redirect of every other path to auth.

use crate::pages::{HomeLinks, Page, page_body};
use axum::{
    Router,
    http::{HeaderValue, StatusCode, Uri, header, uri::PathAndQuery},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use piquel_common::config::Origin;
use piquel_telemetry::HttpTelemetry;
use piquel_ui::{Asset, FONTS, Policies, STYLESHEET};
use topcoat::{
    context::Cx,
    view::{ViewExt, view},
};

/// The health probe piqueld polls. It is free, and quiet in telemetry.
pub(crate) const HEALTH: &str = "/health";

/// Every page's Content-Security-Policy: the stylesheet and its typefaces, on
/// piquel.fr itself, and nothing else. No page has a script or a form.
const POLICY: &str = "default-src 'none'; style-src 'self'; font-src 'self'; \
                      frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// The files every page links, embedded with the executable.
const ASSETS: [Asset; 4] = [STYLESHEET, FONTS[0], FONTS[1], FONTS[2]];

/// How long browsers and shared caches may keep a page: they change only with a
/// release.
const PAGE_CACHE: &str = "public, max-age=300";

/// piquel.fr, which relies on auth at `auth` only to sign people in.
#[derive(Clone)]
pub(crate) struct Site {
    /// Auth's origin, which the homepage links and every other path redirects to.
    auth: Origin,
}

impl Site {
    /// The site of the auth service at `auth`.
    pub(crate) fn new(auth: Origin) -> Self {
        Self { auth }
    }

    /// Every route: the pages, the stylesheet with its typefaces and the health
    /// probe, then a temporary redirect of every other path, with its query, to
    /// the same one on auth, so links sent before the settings moved, such as
    /// security notices', still open their page; browsers keep the fragment.
    /// Temporary, so browsers cache nothing should piquel.fr serve that path
    /// later. Every answer carries the security headers, inside the request
    /// telemetry.
    pub(crate) fn router(self) -> Router {
        let auth = self.auth.serialized();
        let router = Page::ALL
            .into_iter()
            .fold(Router::new(), |router, page| {
                let site = self.clone();
                router.route(
                    page.path(),
                    get(move || async move { site.render(page).await }),
                )
            });
        let router = ASSETS.into_iter().fold(router, |router, asset| {
            router.route(
                &asset.path(),
                get(move || std::future::ready(Self::asset(asset))),
            )
        });
        let router = router
            .route(HEALTH, get(|| std::future::ready(StatusCode::NO_CONTENT)))
            .fallback(move |uri: Uri| {
                let path = uri.path_and_query().map_or("/", PathAndQuery::as_str);
                std::future::ready(Redirect::temporary(&format!("{auth}{path}")))
            })
            .layer(middleware::map_response(|response| {
                std::future::ready(Self::secure(response))
            }));
        HttpTelemetry::default().quiet(&[HEALTH]).wrap(router)
    }

    /// A shared file, at the path naming its content or version, so caches keep
    /// it forever.
    fn asset(asset: Asset) -> Response {
        (
            [
                (header::CONTENT_TYPE, asset.content_type()),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            asset.bytes(),
        )
            .into_response()
    }

    /// Answers with `page` in Piquel's document and the site's frame, whose
    /// status bar links the policies here.
    async fn render(&self, page: Page) -> Response {
        let cx = Cx::default();
        let stylesheet = STYLESHEET.path();
        let (sign_in, register, settings, developers) = (
            self.auth.join("/login"),
            self.auth.join("/register"),
            self.auth.join("/settings"),
            self.auth.join("/developers"),
        );
        let links = HomeLinks {
            sign_in: &sign_in,
            register: &register,
            settings: &settings,
            developers: &developers,
        };
        let header = [("Sign in", sign_in.as_str()), ("Create an account", register.as_str())];
        let html = view! { cx =>
            piquel_ui::document(
                title: page.title(),
                stylesheet: &stylesheet,
                indexable: true,
                piquel_ui::site_shell(
                    home: Page::Home.path(),
                    links: &header,
                    policies: Policies::PATHS,
                    page_body(page: page, links: links)
                )
            )
        }
        .single()
        .await;
        match html {
            Ok(html) => (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/html; charset=utf-8"),
                    ),
                    (
                        header::CONTENT_SECURITY_POLICY,
                        HeaderValue::from_static(POLICY),
                    ),
                    (header::CACHE_CONTROL, HeaderValue::from_static(PAGE_CACHE)),
                ],
                html.render(&cx),
            )
                .into_response(),
            Err(error) => {
                tracing::error!(error = %error, page = page.path(), "page could not be rendered");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }

    /// Adds the headers every answer carries, and forbids caching any that did not
    /// choose: redirects and errors.
    fn secure(mut response: Response) -> Response {
        let headers = response.headers_mut();
        for (name, value) in [
            // No MIME sniffing.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // Links to apps carry no path of piquel.fr.
            (header::REFERRER_POLICY, "strict-origin-when-cross-origin"),
            // No page may be framed.
            (header::X_FRAME_OPTIONS, "DENY"),
            // Keep later visits on HTTPS for a year.
            (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
        response
    }
}

#[cfg(test)]
mod tests {
    //! The site as a browser sees it.
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;

    /// Auth's origin in tests.
    const AUTH: &str = "https://auth.piquel.fr";

    /// `path`'s answer.
    async fn visit(path: &str) -> Response {
        Site::new(AUTH.parse().expect("auth origin"))
            .router()
            .oneshot(
                axum::http::Request::get(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answer")
    }

    /// The homepage and the policies are indexable pages that load nothing but the
    /// stylesheet, and whose footer links the policies here.
    #[tokio::test]
    async fn serves_its_pages() {
        for (page, heading) in [
            (Page::Home, "One passkey for every Piquel app."),
            (Page::Privacy, "Privacy policy"),
            (Page::Terms, "Terms of service"),
        ] {
            let response = visit(page.path()).await;
            assert_eq!(response.status(), StatusCode::OK, "{page:?}");
            assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], POLICY);
            assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
            let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
            let html = String::from_utf8(body.to_vec()).expect("UTF-8");
            assert!(html.contains(heading), "{page:?}");
            assert!(!html.contains("noindex"), "{page:?}");
            assert!(html.contains(r#"href="/privacy""#), "{page:?}");
            assert!(html.contains(&STYLESHEET.path()), "{page:?}");
        }
        for asset in ASSETS {
            let served = visit(&asset.path()).await;
            assert_eq!(served.status(), StatusCode::OK, "{}", asset.path());
        }
    }

    /// Every other path, a sent settings link's included, goes on to auth with its
    /// query, and nobody caches that.
    #[tokio::test]
    async fn sends_every_other_path_to_auth() {
        let response = visit("/settings/emails/verify?remove=1").await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://auth.piquel.fr/settings/emails/verify?remove=1"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
