//! The page a navigation's failure shows, while a `fetch` still reads JSON.

use super::*;
use crate::config::PolicyLinks;
use crate::security::{Explanation, page::ErrorPages};
use sourceorigin_ui::Preferences;

/// A listener's error pages.
fn pages() -> ErrorPages {
    ErrorPages {
        policies: PolicyLinks::on(&crate::tests::WEB_ORIGIN.parse().expect("web origin")),
    }
}

/// The headers of a request whose fetch metadata names `mode`.
fn fetched(mode: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("sec-fetch-mode", HeaderValue::from_str(mode).expect("mode"));
    headers
}

/// `response` as a navigation of the `admin` listener or auth's gets it, and its
/// body.
async fn explained(admin: bool, response: impl IntoResponse) -> (Response, String) {
    let mut response = response.into_response();
    pages()
        .explain(admin, Preferences::default(), &mut response)
        .await;
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20).await.expect("body");
    (
        Response::from_parts(parts, Body::empty()),
        String::from_utf8(body.to_vec()).expect("UTF-8"),
    )
}

/// Navigations are told from fetches by their fetch metadata, or, from a browser
/// that sends none, by whether they accept HTML on a route browsers navigate to,
/// as the routes classify: a client of a protocol or JSON route that happens to
/// accept HTML keeps its JSON, a passkey ceremony's included, and health probes
/// always do.
#[test]
fn navigations_are_told_from_fetches() {
    let navigation = |headers: &HeaderMap, method: Method, path: &str| {
        ErrorPages::navigation(headers, &method, Endpoint::classify(path))
    };
    assert!(navigation(&fetched("navigate"), Method::GET, page::LOGIN));
    assert!(navigation(&fetched("navigate"), Method::POST, oidc::TOKEN));
    assert!(!navigation(
        &fetched("navigate"),
        Method::GET,
        service::READY
    ));
    for mode in ["cors", "same-origin", "no-cors"] {
        assert!(
            !navigation(&fetched(mode), Method::GET, page::LOGIN),
            "{mode}"
        );
    }
    let mut accepting = HeaderMap::new();
    accepting.insert(
        header::ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml"),
    );
    for (method, path) in [
        (Method::GET, page::LOGIN),
        (Method::POST, page::LOGIN),
        (Method::GET, oidc::AUTHORIZE),
        (Method::GET, "/login/github/callback"),
        (Method::GET, "/no-such-page"),
    ] {
        assert!(navigation(&accepting, method, path), "{path}");
    }
    for (method, path) in [
        (Method::POST, oidc::TOKEN),
        (Method::GET, oidc::USERINFO),
        (Method::POST, "/webauthn/authenticate/start"),
        (Method::GET, "/account/passkeys"),
    ] {
        assert!(!navigation(&accepting, method, path), "{path}");
    }
    accepting.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    assert!(!navigation(&accepting, Method::GET, page::LOGIN));
    assert!(!navigation(&HeaderMap::new(), Method::GET, page::LOGIN));
}

/// A refusal's page says what its JSON says, at its status and with its
/// headers, under a policy of its own, and leads back to auth.
#[tokio::test]
async fn a_refusal_navigated_to_is_a_page_saying_why() {
    let refusal = ApiError::too_many_requests(
        "Too many requests. Please wait a minute.",
        std::time::Duration::from_mins(1),
    );
    let (response, page) = explained(false, refusal).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let policy = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .expect("policy");
    assert!(policy.starts_with("default-src 'none';"), "{policy}");
    assert!(page.contains("<h1>Too many requests</h1>"), "{page}");
    assert!(
        page.contains("Too many requests. Please wait a minute."),
        "{page}"
    );
    assert!(
        page.contains(r#"<a class="button" href="/">Go to Origin Auth</a>"#),
        "{page}"
    );
}

/// A failure that explains nothing, such as Topcoat's plain-text server error or
/// an empty `404`, gets its status's own words; the dashboard's lead back to it.
/// A server error's page says only that, whatever the failure explained.
#[tokio::test]
async fn an_unexplained_failure_navigated_to_gets_its_status_s_words() {
    let mut failed = StatusCode::SERVICE_UNAVAILABLE.into_response();
    failed
        .extensions_mut()
        .insert(Explanation("a detail for the logs".to_owned()));
    let (_, page) = explained(false, failed).await;
    assert!(
        page.contains("The service is unavailable right now."),
        "{page}"
    );
    assert!(!page.contains("a detail for the logs"), "{page}");
    let (response, page) = explained(
        true,
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(page.contains("<h1>Something went wrong</h1>"), "{page}");
    assert!(page.contains("Back to the dashboard"), "{page}");
    assert!(!page.contains("internal server error"), "{page}");
    let (response, page) = explained(false, StatusCode::NOT_FOUND).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(page.contains("There is no page at this address."), "{page}");
}

/// Successes, redirects and pages that explain themselves stay as they are.
#[tokio::test]
async fn successes_and_pages_stay_as_they_are() {
    let page = (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<h1>The page's own</h1>",
    );
    for response in [
        page.into_response(),
        StatusCode::OK.into_response(),
        StatusCode::SEE_OTHER.into_response(),
    ] {
        let status = response.status();
        let (response, body) = explained(false, response).await;
        assert_eq!(response.status(), status);
        assert!(!body.contains("Go to Origin Auth"), "{body}");
    }
}
