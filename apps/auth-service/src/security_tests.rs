use super::*;
use axum::{Router, body::Body, http::Request as HttpRequest, middleware, routing::any};
use piquel_repository::DatabaseConfig;
use std::net::{IpAddr, Ipv6Addr};
use tower::ServiceExt;

struct SecurityFixture {
    router: Router,
    peer: SocketAddr,
}
impl SecurityFixture {
    async fn database(max_connections: u32, timeout: std::time::Duration) -> Database {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        Database::connect(
            DatabaseConfig::new_development(&url, max_connections, timeout)
                .expect("database configuration"),
        )
        .await
        .expect("database")
    }
    async fn new() -> Self {
        let database = Self::database(5, std::time::Duration::from_secs(5)).await;
        database.run_migrations().await.expect("migrations");
        let policy = HttpSecurity {
            database,
            auth_origin: "https://auth.piquel.fr".into(),
            settings_origin: "https://piquel.fr".into(),
            client_origins: Arc::new(vec!["https://external.example".into()]),
        };
        let mut router = Router::new();
        for path in [
            "/account/passkeys",
            "/webauthn/authenticate/start",
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/oauth/token",
            "/oauth/userinfo",
            "/oidc/token",
            "/oidc/userinfo",
            "/oidc/logout",
        ] {
            router = router.route(path, any(|| async { StatusCode::ACCEPTED }));
        }
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(UserId::new().as_uuid().as_u128())),
            4321,
        );
        Self {
            router: router.layer(middleware::from_fn_with_state(
                policy,
                HttpSecurity::protect,
            )),
            peer,
        }
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        origin: Option<&str>,
        csrf: bool,
    ) -> Response {
        let mut request = HttpRequest::builder().method(method.clone()).uri(path);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if csrf {
            request = request.header("x-piquel-csrf", "1");
        }
        if method == Method::OPTIONS {
            request = request
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "content-type, x-piquel-csrf",
                );
        }
        let mut request = request.body(Body::empty()).expect("request");
        request.extensions_mut().insert(ConnectInfo(self.peer));
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("response")
    }
    fn exact_cors(response: &Response, origin: &str) {
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            origin
        );
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
            "true"
        );
        assert_eq!(response.headers()[header::VARY], "Origin");
        assert_ne!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    }
    fn denied(response: &Response) {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this complete browser-origin trust-boundary scenario together."
)]
async fn router_enforces_exact_browser_origins_csrf_and_public_client_cors_boundaries() {
    let fixture = SecurityFixture::new().await;
    for origin in ["https://auth.piquel.fr", "https://piquel.fr"] {
        let response = fixture
            .request(Method::POST, "/account/passkeys", Some(origin), true)
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        SecurityFixture::exact_cors(&response, origin);
        let response = fixture
            .request(Method::POST, "/account/passkeys", Some(origin), false)
            .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "approved origin still needs CSRF header"
        );
    }
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://piquel.fr.evil.example"),
        Some("https://auth.piquel.fr:444"),
        Some("http://auth.piquel.fr"),
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
            Some("https://piquel.fr"),
            true,
        )
        .await;
    SecurityFixture::denied(&response);
    let response = fixture
        .request(
            Method::POST,
            "/webauthn/authenticate/start",
            Some("https://auth.piquel.fr"),
            true,
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // OIDC endpoints authenticate their own tokens/client credentials. Browser
    // clients can read public metadata and call protocol APIs, never settings.
    for (method, path) in [
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::GET, "/.well-known/jwks.json"),
        (Method::POST, "/oauth/token"),
        (Method::POST, "/oidc/token"),
        (Method::GET, "/oauth/userinfo"),
        (Method::GET, "/oidc/userinfo"),
    ] {
        let response = fixture
            .request(method, path, Some("https://external.example"), false)
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{path}");
        SecurityFixture::exact_cors(&response, "https://external.example");
    }
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
    for origin in ["https://auth.piquel.fr", "https://piquel.fr"] {
        let response = fixture
            .request(Method::OPTIONS, "/account/passkeys", Some(origin), false)
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        SecurityFixture::exact_cors(&response, origin);
        assert!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .expect("allowed headers")
                .contains("x-piquel-csrf")
        );
    }
    let response = fixture
        .request(
            Method::OPTIONS,
            "/oidc/token",
            Some("https://external.example"),
            false,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    SecurityFixture::exact_cors(&response, "https://external.example");
    for origin in [None, Some("null"), Some("https://evil.example")] {
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn optional_session_preserves_database_failure_instead_of_reporting_signed_out() {
    let database = SecurityFixture::database(1, std::time::Duration::from_millis(50)).await;
    // Exhaust only this test's private pool; the database and all other tests
    // remain usable. A well-formed session cookie must trigger a real lookup.
    let transaction = database.begin().await.expect("hold sole connection");
    assert!(
        optional_session(&database, &HeaderMap::new())
            .await
            .expect("no cookie requires no lookup")
            .is_none()
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "__Host-piquel_session={}",
            BrowserSecret::new().encoded()
        ))
        .expect("cookie"),
    );
    let error = optional_session(&database, &headers)
        .await
        .expect_err("database timeout must propagate");
    assert_eq!(
        error.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    transaction.rollback().await.expect("release connection");
}
