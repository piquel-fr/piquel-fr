use super::*;
use axum::{Router, body::Body, http::Request as HttpRequest, middleware, routing::any};
use piquel_repository::DatabaseConfig;
use std::net::{IpAddr, Ipv6Addr};
use tower::ServiceExt;

struct SecurityFixture {
    router: Router,
    peer: SocketAddr,
    policy: HttpSecurity,
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
            trusted_proxies: Arc::new(vec![]),
            request_timeout: std::time::Duration::from_secs(30),
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
            "/oauth/authorize",
            "/oauth/revoke",
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
                policy.clone(),
                HttpSecurity::protect,
            )),
            peer,
            policy,
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
            "/oauth/token",
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn forwarded_addresses_require_an_explicit_trusted_peer() {
    let mut fixture = SecurityFixture::new().await;
    let mut request = HttpRequest::builder()
        .header("x-forwarded-for", "192.0.2.7")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(fixture.peer));
    assert_eq!(
        fixture.policy.client_ip(&request).expect("direct peer"),
        fixture.peer.ip()
    );
    fixture.policy.trusted_proxies = Arc::new(vec![IpNet::from(fixture.peer.ip())]);
    assert_eq!(
        fixture.policy.client_ip(&request).expect("trusted header"),
        "192.0.2.7".parse::<IpAddr>().expect("IP")
    );
    request
        .headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("192.0.2.8"));
    assert!(fixture.policy.client_ip(&request).is_err());
    request.headers_mut().remove("x-forwarded-for");
    assert!(fixture.policy.client_ip(&request).is_err());
    request.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("192.0.2.7, 192.0.2.8"),
    );
    assert!(fixture.policy.client_ip(&request).is_err());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rate_limit_deadline_includes_a_blocked_database_query() {
    let mut fixture = SecurityFixture::new().await;
    let bucket = Sha256::digest(format!("token:{}", fixture.peer.ip()).as_bytes());
    let mut transaction = fixture.policy.database.begin().await.expect("transaction");
    transaction
        .security()
        .allow_request(&bucket, 120)
        .await
        .expect("hold bucket lock");
    fixture.policy.request_timeout = std::time::Duration::from_millis(100);
    fixture.router = Router::new()
        .route("/oauth/token", any(|| async { StatusCode::ACCEPTED }))
        .layer(middleware::from_fn_with_state(
            fixture.policy.clone(),
            HttpSecurity::protect,
        ));
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        fixture.request(Method::POST, "/oauth/token", None, false),
    )
    .await
    .expect("whole request is bounded");
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    transaction.rollback().await.expect("release lock");
    assert_eq!(
        fixture
            .request(Method::POST, "/oauth/token", None, false)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rate_budgets_are_separate_and_unknown_paths_do_not_consume_them() {
    let fixture = SecurityFixture::new().await;
    for _ in 0..125 {
        assert_eq!(
            fixture
                .request(Method::GET, "/login/nonexistent", None, false)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let bucket = Sha256::digest(format!("token:{}", fixture.peer.ip()).as_bytes());
    for _ in 0..120 {
        fixture
            .policy
            .database
            .security()
            .allow_request(&bucket, 120)
            .await
            .expect("fill token budget");
    }
    assert_eq!(
        fixture
            .request(Method::POST, "/oauth/token", None, false)
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        fixture
            .request(
                Method::POST,
                "/webauthn/authenticate/start",
                Some("https://auth.piquel.fr"),
                true
            )
            .await
            .status(),
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn trusted_proxy_clients_have_independent_budgets() {
    let mut fixture = SecurityFixture::new().await;
    fixture.policy.trusted_proxies = Arc::new(vec![IpNet::from(fixture.peer.ip())]);
    let bucket = Sha256::digest(b"token:192.0.2.17");
    for _ in 0..120 {
        fixture
            .policy
            .database
            .security()
            .allow_request(&bucket, 120)
            .await
            .expect("fill first client's budget");
    }
    let router = Router::new()
        .route("/oauth/token", any(|| async { StatusCode::ACCEPTED }))
        .layer(middleware::from_fn_with_state(
            fixture.policy,
            HttpSecurity::protect,
        ));
    for (client, expected) in [
        ("192.0.2.17", StatusCode::TOO_MANY_REQUESTS),
        ("192.0.2.18", StatusCode::ACCEPTED),
    ] {
        let mut request = HttpRequest::builder()
            .method(Method::POST)
            .uri("/oauth/token")
            .header("x-forwarded-for", client)
            .body(Body::empty())
            .expect("request");
        request.extensions_mut().insert(ConnectInfo(fixture.peer));
        assert_eq!(
            router
                .clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            expected
        );
    }
}
