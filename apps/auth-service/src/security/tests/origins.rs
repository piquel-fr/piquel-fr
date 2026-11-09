//! The browser-origin, CSRF and CORS rules each endpoint family enforces.

use super::*;

/// Exercises exact-origin, CSRF and public-client boundaries across endpoint families.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this complete browser-origin trust-boundary scenario together."
)]
async fn router_enforces_exact_browser_origins_csrf_and_public_client_cors_boundaries() {
    let fixture = SecurityFixture::new().await;
    let own = "https://auth.sourceorigin.dev";
    let response = fixture
        .request(Method::POST, "/account/passkeys", Some(own), true)
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    SecurityFixture::exact_cors(&response, own);
    let response = fixture
        .request(Method::POST, "/account/passkeys", Some(own), false)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "approved origin still needs CSRF header"
    );
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://sourceorigin.dev"),
        Some("https://auth.sourceorigin.dev.evil.example"),
        Some("https://auth.sourceorigin.dev:444"),
        Some("http://auth.sourceorigin.dev"),
    ] {
        let response = fixture
            .request(Method::POST, "/account/passkeys", origin, true)
            .await;
        SecurityFixture::denied(&response);
    }
    let response = fixture
        .request(
            Method::POST,
            "/webauthn/authenticate/start",
            Some("https://sourceorigin.dev"),
            true,
        )
        .await;
    SecurityFixture::denied(&response);
    let response = fixture
        .request(
            Method::POST,
            "/webauthn/authenticate/start",
            Some(own),
            true,
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Any page may read the public metadata, keys and audit checkpoints, without
    // credentials.
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/audit/checkpoints",
        "/audit/checkpoints/latest",
    ] {
        for (method, status) in [
            (Method::GET, StatusCode::ACCEPTED),
            (Method::OPTIONS, StatusCode::NO_CONTENT),
        ] {
            let response = fixture
                .request(method, path, Some("https://tool.example"), false)
                .await;
            assert_eq!(response.status(), status, "{path}");
            assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .is_none()
            );
        }
    }
    // OIDC endpoints authenticate their own tokens/client credentials. Browser
    // clients can call protocol APIs, never settings.
    for (method, path) in [
        (Method::POST, "/oauth/token"),
        (Method::POST, "/oauth/revoke"),
        (Method::GET, "/oidc/userinfo"),
        (Method::POST, "/oidc/userinfo"),
    ] {
        let response = fixture
            .request(method, path, Some("https://external.example"), false)
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{path}");
        SecurityFixture::exact_cors(&response, "https://external.example");
    }
    // A browser form navigation from an RP does not use the settings CSRF header.
    let response = fixture
        .request(
            Method::POST,
            "/oauth/authorize",
            Some("https://external.example"),
            false,
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    for method in [Method::GET, Method::POST, Method::OPTIONS] {
        let response = fixture
            .request(
                method,
                "/account/passkeys",
                Some("https://external.example"),
                true,
            )
            .await;
        SecurityFixture::denied(&response);
    }
    let response = fixture
        .request(Method::OPTIONS, "/account/passkeys", Some(own), false)
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    SecurityFixture::exact_cors(&response, own);
    // A public client sends its codes and tokens, never cookies or Origin Auth's CSRF header.
    let response = fixture
        .request(
            Method::OPTIONS,
            "/oauth/token",
            Some("https://external.example"),
            false,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    SecurityFixture::exact_cors(&response, "https://external.example");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "content-type, authorization"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "GET, POST, OPTIONS"
    );
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://sourceorigin.dev"),
    ] {
        let response = fixture
            .request(Method::OPTIONS, "/account/passkeys", origin, false)
            .await;
        SecurityFixture::denied(&response);
    }
    // External RP-initiated logout reaches its own validating handler. This
    // dummy handler only proves delegation and cannot log out a real session.
    let response = fixture
        .request(
            Method::GET,
            "/oidc/logout",
            Some("https://external.example"),
            false,
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}

/// Browser origin and mutation proof are required everywhere except protocol
/// endpoints, and pages, which have their own rule.
#[test]
fn endpoint_policy_requires_browser_proof_outside_protocol_endpoints() {
    let site = site();
    let check = |endpoint, headers: &HeaderMap, allowed, mutation| {
        HttpSecurity::check_browser(endpoint, headers, allowed, mutation, &site).is_ok()
    };
    for (endpoint, protocol) in [
        (Endpoint::OAuthBackChannel, true),
        (Endpoint::UserInfo, true),
        (Endpoint::Discovery, false),
        (Endpoint::Checkpoints, false),
        (Endpoint::Health, false),
        (Endpoint::Authorize, true),
        (Endpoint::Logout, true),
        (Endpoint::Account, false),
        (Endpoint::Other, false),
    ] {
        assert_eq!(endpoint.is_protocol(), protocol);
        let anonymous = HeaderMap::new();
        let mut browser = HeaderMap::new();
        browser.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        // Unapproved mutations and cross-origin reads only reach protocol handlers.
        assert_eq!(check(endpoint, &anonymous, false, true), protocol);
        assert_eq!(check(endpoint, &browser, false, false), protocol);
        assert!(check(endpoint, &anonymous, false, false));
        // Approved mutations still need CSRF proof.
        assert_eq!(check(endpoint, &browser, true, true), protocol);
        browser.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        assert!(check(endpoint, &browser, true, true));
    }
}

/// Anyone may navigate to a page, but only auth's own pages may post its form:
/// `Sec-Fetch-Site` decides when the browser sends it, then `Origin`. A form on a
/// `no-referrer` page sends `Origin: null`, and the CSRF header changes nothing.
#[test]
fn pages_take_forms_only_from_auth_pages() {
    let own = Some("https://auth.sourceorigin.dev");
    for (fetch_site, origin, csrf, mutation, accepted) in [
        (None, None, false, false, true),
        (
            Some("cross-site"),
            Some("https://evil.example"),
            false,
            false,
            true,
        ),
        (Some("same-origin"), Some("null"), false, true, true),
        (Some("same-origin"), None, false, true, true),
        (None, own, false, true, true),
        (Some("same-site"), own, false, true, false),
        (Some("cross-site"), Some("null"), true, true, false),
        (Some("none"), None, false, true, false),
        (None, Some("null"), false, true, false),
        (None, None, true, true, false),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(fetch_site) = fetch_site {
            headers.insert(FETCH_SITE_HEADER, HeaderValue::from_static(fetch_site));
        }
        if let Some(origin) = origin {
            headers.insert(header::ORIGIN, HeaderValue::from_static(origin));
        }
        if csrf {
            headers.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        }
        assert_eq!(
            HttpSecurity::check_browser(Endpoint::Page, &headers, true, mutation, &site()).is_ok(),
            accepted,
            "{fetch_site:?} {origin:?} csrf={csrf} mutation={mutation}"
        );
    }
}
