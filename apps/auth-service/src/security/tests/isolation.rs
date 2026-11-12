//! The isolation headers and the one Content-Security-Policy every response
//! carries.

use super::*;
use crate::security::{FormTargets, content::ContentPolicy};

/// Decorates `response` as [`HttpSecurity::protect`] does on the given CORS `grant`.
fn decorated(response: impl IntoResponse, grant: Option<CorsGrant>) -> Response {
    let mut response = response.into_response();
    HttpSecurity::decorate(&mut response, grant);
    response
}

/// Every response keeps other sites' pages from holding a window on it and from
/// using powerful features but passkeys and the clipboard; only public responses
/// may be embedded by other sites, and the build assets by SourceOrigin's own.
#[test]
fn every_response_is_isolated_and_only_public_ones_embeddable() {
    for (response, resource_policy) in [
        (decorated(StatusCode::OK, None), "same-origin"),
        (decorated(StatusCode::FORBIDDEN, None), "same-origin"),
        (
            decorated(Cached(CacheClass::Immutable, StatusCode::OK), None),
            "same-site",
        ),
        (
            decorated(StatusCode::OK, Some(CorsGrant::Public)),
            "cross-origin",
        ),
    ] {
        let headers = response.headers();
        assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
        assert_eq!(headers["cross-origin-resource-policy"], resource_policy);
        let permissions = headers["permissions-policy"].to_str().expect("text");
        assert!(
            permissions.starts_with(
                "publickey-credentials-get=(self), publickey-credentials-create=(self), clipboard-write=(self),"
            ),
            "{permissions}"
        );
        assert!(permissions.contains(" camera=(),"), "{permissions}");
    }
}

/// A page widens its listener's policy only by the origins its forms redirect on
/// to: a target that names anything else could widen the policy past its
/// `form-action`, so it is left out.
#[test]
fn a_page_widens_only_form_action_by_origins() {
    let config = crate::AuthConfig::test(&crate::tests::AUTH_ORIGIN.parse().expect("origin"));
    let content = ContentPolicy::auth(&config);
    let mut response = StatusCode::OK.into_response();
    response.extensions_mut().insert(FormTargets(vec![
        "https://app.example".to_owned(),
        "https://app.example; script-src *".to_owned(),
        "*".to_owned(),
        "'unsafe-inline'".to_owned(),
    ]));
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
