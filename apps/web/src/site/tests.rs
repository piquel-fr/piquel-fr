//! The site as a browser sees it.
use super::*;
use axum::body::{Body, to_bytes};
use tower::ServiceExt;

/// Auth's origin in tests.
const AUTH: &str = "https://auth.sourceorigin.dev";

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
        (Page::Home, "One passkey for every SourceOrigin app."),
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
/// query, and nobody caches that. The redirect is isolated as a page is.
#[tokio::test]
async fn sends_every_other_path_to_auth() {
    let response = visit("/settings/emails/verify?remove=1").await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://auth.sourceorigin.dev/settings/emails/verify?remove=1"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let headers = response.headers();
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], POLICY);
    assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
    assert_eq!(headers["cross-origin-resource-policy"], "same-origin");
    assert_eq!(
        headers["permissions-policy"],
        sourceorigin_common::protocol::isolation::PERMISSIONS_POLICY
    );
}
