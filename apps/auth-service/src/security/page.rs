//! The page a browser's navigation gets when its request fails before a page of
//! its own could explain it: a refusal of the security layer, a JSON route
//! opened as a page, an address with no page, or Topcoat's plain-text failure.
//! `fetch` requests still read JSON.

use super::{ApiError, BrowserCookie};
use crate::{assets::EmbeddedAssets, config::PolicyLinks, routes};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use sourceorigin_telemetry::HttpTelemetry;
use topcoat::{
    context::Cx,
    view::{ViewExt, view},
};

/// What a failure tells the user, such as an [`ApiError`]'s message, which its
/// response keeps so a navigation's page can say it too.
#[derive(Clone, Debug)]
pub(crate) struct Explanation(pub(crate) String);

/// The error pages of one listener: auth's, or the admin dashboard's, coloured
/// as it, each linking SourceOrigin's `policies`.
#[derive(Clone)]
pub(super) struct ErrorPages {
    /// SourceOrigin's policies, which every page's status bar links.
    pub(super) policies: PolicyLinks,
    /// Whether the pages are the admin dashboard's.
    pub(super) admin: bool,
}

impl ErrorPages {
    /// The policy of an error page: the stylesheet and its typefaces, nothing
    /// else, and no form, frame or script.
    const POLICY: &'static str = "default-src 'none'; style-src 'self'; font-src 'self'; \
         img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

    /// Whether the request with `headers` is a browser's navigation, which shows a
    /// page, rather than a `fetch`, which reads JSON: by its fetch metadata, or,
    /// from a browser that sends none, by whether it accepts HTML.
    pub(super) fn navigation(headers: &HeaderMap) -> bool {
        let text = |name| headers.get(name).and_then(|value| value.to_str().ok());
        match text("sec-fetch-mode") {
            Some(mode) => mode == "navigate",
            None => {
                text(header::ACCEPT.as_str()).is_some_and(|accept| accept.contains("text/html"))
            }
        }
    }

    /// What a page at `status` is titled, and what it says when the failure
    /// itself explains nothing.
    fn wording(status: StatusCode) -> (&'static str, &'static str) {
        match status {
            StatusCode::BAD_REQUEST => ("This request could not be read", "Go back and try again."),
            StatusCode::UNAUTHORIZED => ("Sign in to continue", "Sign in, then try again."),
            StatusCode::FORBIDDEN => ("Not allowed", "This request is not allowed."),
            StatusCode::NOT_FOUND => ("Page not found", "There is no page at this address."),
            StatusCode::PAYLOAD_TOO_LARGE => (
                "Too large",
                "What you sent is too large. Shorten it and try again.",
            ),
            StatusCode::MISDIRECTED_REQUEST => {
                ("Wrong address", "This address is not served here.")
            }
            StatusCode::TOO_MANY_REQUESTS => {
                ("Too many requests", "Please wait a minute, then try again.")
            }
            StatusCode::SERVICE_UNAVAILABLE => (
                "Unavailable",
                "The service is unavailable right now. Please try again.",
            ),
            StatusCode::GATEWAY_TIMEOUT => {
                ("Timed out", "This request took too long. Please try again.")
            }
            status if status.is_server_error() => (
                "Something went wrong",
                "Something went wrong on our side. Please try again.",
            ),
            _ => (
                "This request failed",
                "This request could not be completed.",
            ),
        }
    }

    /// Makes `response`, the failure of a navigation with `headers`, its page: its
    /// status and headers stay, such as `Retry-After`, and a server error's page
    /// shows its trace ID. A success, a redirect or a page already explaining
    /// itself stays as it is, and so does the failure if its page cannot render.
    pub(super) async fn explain(&self, headers: &HeaderMap, response: &mut Response) {
        let status = response.status();
        let html = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html"));
        if !(status.is_client_error() || status.is_server_error()) || html {
            return;
        }
        let (title, default) = Self::wording(status);
        let message = response
            .extensions()
            .get::<Explanation>()
            .map_or(default, |explanation| explanation.0.as_str());
        let page = match self.render(headers, status, title, message).await {
            Ok(page) => page,
            Err(error) => {
                ApiError::log_error(&*error);
                return;
            }
        };
        *response.body_mut() = Body::from(page);
        let headers = response.headers_mut();
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(Self::POLICY),
        );
    }

    /// The page titled `title` saying `message`, at `status`, in the theme the
    /// browser sending `headers` prefers.
    async fn render(
        &self,
        headers: &HeaderMap,
        status: StatusCode,
        title: &str,
        message: &str,
    ) -> topcoat::Result<String> {
        let cx = &Cx::default();
        let stylesheet = EmbeddedAssets::STYLESHEET.path();
        let back = if self.admin {
            "Back to the dashboard"
        } else {
            "Go to Origin Auth"
        };
        Ok(view! { cx =>
            sourceorigin_ui::document(
                title: title,
                stylesheet: &stylesheet,
                preferences: BrowserCookie::read_preferences(headers),
                admin: self.admin,
                sourceorigin_ui::auth_shell(
                    home: routes::page::ROOT,
                    reference: HttpTelemetry::trace_id(status),
                    admin: self.admin,
                    policies: self.policies.links(),
                    sourceorigin_ui::error_page(
                        title: title,
                        message: message,
                        home: routes::page::ROOT,
                        back: back,
                    )
                )
            )
        }
        .single()
        .await?
        .render(cx))
    }
}
