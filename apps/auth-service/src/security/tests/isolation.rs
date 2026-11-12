//! The isolation headers and the one Content-Security-Policy every response
//! carries.

use super::*;
use crate::security::{FormTarget, FormTargets, content::ContentPolicy};
use sourceorigin_common::protocol::isolation;

/// Decorates `response` as [`HttpSecurity::protect`] does on the given CORS `grant`.
fn decorated(response: impl IntoResponse, grant: Option<CorsGrant>) -> Response {
    let mut response = response.into_response();
    HttpSecurity::decorate(&mut response, grant);
    response
}

/// Every response keeps other sites' pages from holding a window on it and from
/// using powerful features but passkeys and the clipboard; only public responses
/// may be embedded by other sites.
#[test]
fn every_response_is_isolated_and_only_public_ones_embeddable() {
    for (response, resource_policy) in [
        (decorated(StatusCode::OK, None), "same-origin"),
        (decorated(StatusCode::FORBIDDEN, None), "same-origin"),
        (
            decorated(Cached(CacheClass::Immutable, StatusCode::OK), None),
            "same-origin",
        ),
        (
            decorated(StatusCode::OK, Some(CorsGrant::Public)),
            "cross-origin",
        ),
    ] {
        let headers = response.headers();
        assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
        assert_eq!(headers["cross-origin-resource-policy"], resource_policy);
        assert_eq!(headers["permissions-policy"], isolation::PERMISSIONS_POLICY);
    }
}

/// A page's forms may redirect on only to origins a policy can name: never an IP
/// address, such as a native app's loopback callback, nor anything but the origin.
#[test]
fn form_targets_are_origins_a_policy_can_name() {
    let target = |url: &str| FormTarget::of(&url::Url::parse(url).expect("URL"));
    assert_eq!(
        target("https://app.example:8443/callback?state=x#y"),
        target("https://app.example:8443")
    );
    for url in [
        "http://127.0.0.1:4100/callback",
        "http://[::1]/callback",
        "com.example.app:/callback",
        "https://bad_label.example/",
    ] {
        assert_eq!(target(url), None, "{url}");
    }
}

/// A page widens its listener's policy only in its `form-action`, by the origins
/// it names.
#[test]
fn a_page_widens_only_form_action() {
    let config = crate::AuthConfig::test(&crate::tests::AUTH_ORIGIN.parse().expect("origin"));
    let content = ContentPolicy::auth(&config).expect("policy");
    let app = FormTarget::of(&url::Url::parse("https://app.example/callback").expect("URL"));
    let mut response = StatusCode::OK.into_response();
    response
        .extensions_mut()
        .insert(FormTargets(app.into_iter().collect()));
    content.set_on(&mut response);
    let policy = crate::tests::policy(&response);
    assert!(policy.starts_with("default-src 'none'; "), "{policy}");
    assert!(
        policy.ends_with("; base-uri 'none'; form-action 'self' https://app.example"),
        "{policy}"
    );
}

/// The policy reaches every response, not only pages: refusals, routes' own
/// answers and unknown paths.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn every_response_carries_the_listener_s_policy() {
    let fixture = SecurityFixture::new().await;
    for (path, origin, status) in [
        ("/oauth/token", None, StatusCode::ACCEPTED),
        (
            "/account/passkeys",
            Some("https://evil.example"),
            StatusCode::FORBIDDEN,
        ),
        ("/no-such-route", None, StatusCode::NOT_FOUND),
    ] {
        let response = fixture.request(Method::GET, path, origin, false).await;
        assert_eq!(response.status(), status, "{path}");
        let policy = crate::tests::policy(&response);
        assert!(
            policy.starts_with("default-src 'none'; ") && policy.ends_with("; form-action 'self'"),
            "{path}: {policy}"
        );
    }
}
