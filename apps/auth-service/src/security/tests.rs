//! Focused persistence and security contract tests.

use super::*;
use crate::routes::federation;
use crate::tests::Replicas;
use axum::{Router, body::Body, http::Request as HttpRequest, middleware, routing::any};
use piquel_common::{TokenId, clients::ClientKind};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseConfig, InsertSession, InsertUser};
use std::net::{IpAddr, Ipv6Addr};
use tower::ServiceExt;

impl RequestContext {
    /// The context of a request from a documentation address, for handler tests
    /// that bypass [`HttpSecurity::protect`].
    pub(crate) const TEST: Self = Self(RequestOrigin {
        client_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        user_agent_family: Some(UserAgentFamily::Firefox),
    });
}

/// Asserts that `response` asks the frontend to confirm the session with a passkey
/// at most [`CONFIRMATION_MAX_AGE`] seconds old, in the stable JSON shape.
pub(crate) async fn assert_step_up_required(response: Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body"),
    )
    .expect("JSON");
    assert_eq!(
        body,
        serde_json::json!({
            "error": "Confirm with your passkey to continue.",
            "code": "step_up_required",
            "max_age": CONFIRMATION_MAX_AGE,
        })
    );
}

/// An isolated request router and database for HTTP trust-boundary scenarios.
struct SecurityFixture {
    /// Dummy routes protected by the production middleware.
    router: Router,
    /// Unique peer address separates concurrent test budgets.
    peer: SocketAddr,
    /// Editable policy for proxy and deadline scenarios.
    policy: HttpSecurity,
}
impl SecurityFixture {
    /// Connects an isolated test pool with caller-selected acquisition bounds.
    async fn database(max_connections: u32, timeout: std::time::Duration) -> Database {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name an isolated PostgreSQL database");
        Database::connect(
            DatabaseConfig::new(&url, max_connections, timeout).expect("database configuration"),
        )
        .await
        .expect("database")
    }
    /// Builds a test policy with exact browser origins and unique client buckets.
    /// A public client calls back to `https://external.example`.
    async fn new() -> Self {
        let database = Self::database(5, std::time::Duration::from_secs(5)).await;
        database.run_migrations().await.expect("migrations");
        database
            .oidc()
            .create_client(&crate::tests::registration(
                ClientKind::Public,
                "https://external.example",
            ))
            .await
            .expect("public client");
        let policy = HttpSecurity {
            trusted_proxies: Arc::new(vec![]),
            request_timeout: std::time::Duration::from_secs(30),
            database,
            auth_origin: "https://auth.piquel.fr".into(),
            frontends: FrontendOrigins::new([&"https://piquel.fr/settings"
                .parse()
                .expect("settings URL")]),
        };
        let mut router = Router::new();
        for path in [
            "/account/passkeys",
            "/webauthn/authenticate/start",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
            "/oauth/token",
            "/oauth/authorize",
            "/oauth/revoke",
            "/oidc/userinfo",
            "/oidc/logout",
            "/session",
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
    /// Sends a request with selected browser proof and explicit peer metadata.
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
    /// Checks credentialed CORS reflects exactly the approved origin.
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
    /// Checks rejected origins receive browser isolation headers and no CORS grant.
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
/// Exercises exact-origin, CSRF and public-client boundaries across endpoint families.
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

    // Any page may read the public metadata and keys, without credentials.
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
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
/// A session lookup failure stays a server error rather than becoming an anonymous session.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn optional_session_preserves_database_failure_instead_of_reporting_signed_out() {
    // The timeout also bounds the first connection, so it leaves room for
    // connecting while other database tests run.
    let database = SecurityFixture::database(1, std::time::Duration::from_secs(1)).await;
    // Exhaust only this test's private pool; the database and all other tests
    // remain usable. A well-formed session cookie must trigger a real lookup.
    let transaction = database.begin().await.expect("hold sole connection");
    assert!(
        Session::optional(&database, &HeaderMap::new())
            .await
            .expect("no cookie requires no lookup")
            .is_none()
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "__Host-piquel_session={}",
            Secret::generate().expect("browser secret").encoded()
        ))
        .expect("cookie"),
    );
    let error = Session::optional(&database, &headers)
        .await
        .expect_err("database timeout must propagate");
    assert_eq!(
        ApiError::from(error).into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    transaction.rollback().await.expect("release connection");
}
/// Only configured ingress peers may supply a single forwarded client address.
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
/// The request deadline also bounds waiting for a locked rate-limit bucket.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rate_limit_deadline_includes_a_blocked_database_query() {
    let mut fixture = SecurityFixture::new().await;
    let bucket = Digest::sha256(format!("token:{}", fixture.peer.ip()).as_bytes());
    let mut transaction = fixture.policy.database.begin().await.expect("transaction");
    transaction
        .security()
        .allow_request(bucket.as_bytes(), 120)
        .await
        .expect("hold bucket lock");
    // The deadline also bounds the request after the lock is released, so it
    // leaves room for queries while other database tests run.
    fixture.policy.request_timeout = std::time::Duration::from_secs(1);
    fixture.router = Router::new()
        .route("/oauth/token", any(|| async { StatusCode::ACCEPTED }))
        .layer(middleware::from_fn_with_state(
            fixture.policy.clone(),
            HttpSecurity::protect,
        ));
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
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
/// Unknown paths do not drain budgets and login remains available after token exhaustion.
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
    let bucket = Digest::sha256(format!("token:{}", fixture.peer.ip()).as_bytes());
    for _ in 0..120 {
        fixture
            .policy
            .database
            .security()
            .allow_request(bucket.as_bytes(), 120)
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
/// Reads spend their budget and then get a retry delay, without draining other budgets.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn reads_exhaust_their_own_budget() {
    let fixture = SecurityFixture::new().await;
    for _ in 0..REQUESTS_PER_MINUTE {
        assert_eq!(
            fixture
                .request(Method::GET, "/oidc/userinfo", None, false)
                .await
                .status(),
            StatusCode::ACCEPTED
        );
    }
    let response = fixture
        .request(Method::GET, "/oidc/userinfo", None, false)
        .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], RETRY_AFTER_SECONDS);
    assert_eq!(
        fixture
            .request(Method::GET, "/session", None, false)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
}
/// One client's budget is shared across replicas: alternating between them, the
/// request after the budget is still rejected.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn replicas_share_one_budget() {
    let replicas = Replicas::new().await;
    let status = async |router: &Router| {
        let request = HttpRequest::get("/session")
            .body(Body::empty())
            .expect("request");
        router
            .clone()
            .oneshot(request)
            .await
            .expect("response")
            .status()
    };
    for index in 0..REQUESTS_PER_MINUTE {
        let router = if index % 2 == 0 {
            &replicas.a
        } else {
            &replicas.b
        };
        assert_eq!(status(router).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(status(&replicas.a).await, StatusCode::TOO_MANY_REQUESTS);
}
/// A trusted proxy shares each budget by forwarded client IP rather than ingress IP.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn trusted_proxy_clients_have_independent_budgets() {
    let mut fixture = SecurityFixture::new().await;
    fixture.policy.trusted_proxies = Arc::new(vec![IpNet::from(fixture.peer.ip())]);
    let bucket = Digest::sha256(b"token:192.0.2.17");
    for _ in 0..120 {
        fixture
            .policy
            .database
            .security()
            .allow_request(bucket.as_bytes(), 120)
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

/// Every route that verifies a token or queries the database has a budget, reads
/// included; only in-memory discovery and health probes are free.
#[test]
fn routes_doing_real_work_have_budgets() {
    for (path, budget) in [
        (service::LIVE, None),
        (service::READY, None),
        (oidc::DISCOVERY, None),
        (oidc::OAUTH_METADATA, None),
        (oidc::JWKS, None),
        (oidc::TOKEN, Some(RateCategory::Token)),
        (oidc::PAR, Some(RateCategory::Token)),
        (oidc::USERINFO, Some(RateCategory::UserInfo)),
        (oidc::LOGOUT, Some(RateCategory::Login)),
        (oidc::AUTHORIZE, Some(RateCategory::Login)),
        (oidc::AUTHORIZE_RESUME, Some(RateCategory::Login)),
        ("/oauth/authorize/transaction/1", Some(RateCategory::Login)),
        (passkey::SESSION, Some(RateCategory::Account)),
        (passkey::LIST, Some(RateCategory::Account)),
        (federation::IDENTITIES, Some(RateCategory::Account)),
        (federation::PENDING, Some(RateCategory::Login)),
    ] {
        assert_eq!(Endpoint::classify(path).rate_category(), budget, "{path}");
    }
}

/// Browser origin and mutation proof are required everywhere except protocol endpoints.
#[test]
fn endpoint_policy_requires_browser_proof_outside_protocol_endpoints() {
    for (endpoint, protocol) in [
        (Endpoint::OAuthBackChannel, true),
        (Endpoint::UserInfo, true),
        (Endpoint::Discovery, false),
        (Endpoint::Health, false),
        (Endpoint::Authorize, true),
        (Endpoint::Logout, true),
        (Endpoint::Account, false),
        (Endpoint::Login, false),
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
        assert_eq!(
            HttpSecurity::check_browser(endpoint, &anonymous, false, true).is_ok(),
            protocol
        );
        assert_eq!(
            HttpSecurity::check_browser(endpoint, &browser, false, false).is_ok(),
            protocol
        );
        assert!(HttpSecurity::check_browser(endpoint, &anonymous, false, false).is_ok());
        // Approved mutations still need CSRF proof.
        assert_eq!(
            HttpSecurity::check_browser(endpoint, &browser, true, true).is_ok(),
            protocol
        );
        browser.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        assert!(HttpSecurity::check_browser(endpoint, &browser, true, true).is_ok());
    }
}

/// Forwarded addresses accept one IP and retain diagnostics for malformed header text or syntax.
#[test]
fn forwarded_address_parser_requires_one_address_and_preserves_causes() {
    let mut headers = HeaderMap::new();
    assert!(matches!(
        HttpSecurity::forwarded_ip(&headers),
        Err(HttpSecurityError::MissingForwardedAddress)
    ));
    for valid in ["192.0.2.7", "2001:db8::7"] {
        headers.insert(
            FORWARDED_FOR_HEADER,
            HeaderValue::from_str(valid).expect("header"),
        );
        assert_eq!(
            HttpSecurity::forwarded_ip(&headers).expect("forwarded address"),
            valid.parse::<IpAddr>().expect("IP")
        );
    }
    headers.append(FORWARDED_FOR_HEADER, HeaderValue::from_static("192.0.2.8"));
    assert!(matches!(
        HttpSecurity::forwarded_ip(&headers),
        Err(HttpSecurityError::MultipleForwardedHeaders)
    ));
    headers.insert(
        FORWARDED_FOR_HEADER,
        HeaderValue::from_static("192.0.2.7, 192.0.2.8"),
    );
    let error = HttpSecurity::forwarded_ip(&headers).expect_err("one address required");
    assert!(matches!(error, HttpSecurityError::ForwardedAddress(_)));
    assert!(std::error::Error::source(&error).is_some());
    headers.insert(
        FORWARDED_FOR_HEADER,
        HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
    );
    let error = HttpSecurity::forwarded_ip(&headers).expect_err("HTTP text required");
    assert!(matches!(error, HttpSecurityError::ForwardedHeader(_)));
    assert!(std::error::Error::source(&error).is_some());
}

/// A confirmation counts from its own timestamp, against each action's maximum age.
#[test]
fn confirmation_age_is_fixed_from_its_timestamp() {
    let session = |age: Option<i64>| {
        let now = Utc::now();
        StoredSession {
            id: SessionId::new(),
            user_id: UserId::new(),
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now - Duration::days(1),
            expires_at: now + Duration::days(1),
            last_seen_at: now,
            revoked_at: None,
            passkey_confirmed_at: age.map(|age| now - Duration::seconds(age)),
        }
    };
    assert!(Confirmed::<CONFIRMATION_MAX_AGE>::check(&session(Some(290))).is_ok());
    for age in [None, Some(310), Some(86_400)] {
        assert!(matches!(
            Confirmed::<CONFIRMATION_MAX_AGE>::check(&session(age)),
            Err(SessionError::StepUpRequired {
                max_age: CONFIRMATION_MAX_AGE
            })
        ));
    }
    assert!(matches!(
        Confirmed::<60>::check(&session(Some(90))),
        Err(SessionError::StepUpRequired { max_age: 60 })
    ));
}

/// A confirmed change holds the session row, so a racing logout waits for it, and a
/// change after logout fails.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confirmed_changes_serialize_with_logout() {
    let database = SecurityFixture::database(5, std::time::Duration::from_secs(5)).await;
    database.run_migrations().await.expect("migrations");
    let user_id = UserId::new();
    let mut tx = database.begin().await.expect("transaction");
    tx.users()
        .insert(&InsertUser {
            id: user_id,
            username: format!("lock_{}", &TokenId::new().to_string()[24..]),
            display_name: "Lock test".into(),
        })
        .await
        .expect("user");
    let secret = Session::create(
        &mut tx,
        RequestContext::TEST,
        user_id,
        AuthenticationMethod::Passkey,
    )
    .await
    .expect("session");
    tx.commit().await.expect("commit");
    let session = database
        .sessions()
        .find_active_by_browser_secret(secret.digest().as_bytes())
        .await
        .expect("lookup")
        .expect("session");
    let id = session.id;
    let confirmed: Confirmed = Confirmed(session);
    let mut change = database.begin().await.expect("change transaction");
    confirmed
        .lock(&mut change)
        .await
        .expect("passkey sign-in confirms");
    let logout = tokio::spawn({
        let database = database.clone();
        async move { database.sessions().revoke(id).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!logout.is_finished(), "logout must wait for the change");
    change.commit().await.expect("commit change");
    assert!(logout.await.expect("logout task").expect("logout"));
    let mut change = database.begin().await.expect("change transaction");
    assert!(matches!(
        confirmed.lock(&mut change).await,
        Err(SessionError::Missing)
    ));
}

/// A session that expires while a change waits for the account lock is rejected once
/// the lock is acquired, even though the lookup compares with the transaction's start.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn session_lock_rechecks_expiry_after_waiting() {
    let database = SecurityFixture::database(5, std::time::Duration::from_secs(5)).await;
    database.run_migrations().await.expect("migrations");
    let user_id = UserId::new();
    let now = Utc::now();
    let mut tx = database.begin().await.expect("transaction");
    tx.users()
        .insert(&InsertUser {
            id: user_id,
            username: format!("lock_{}", &TokenId::new().to_string()[24..]),
            display_name: "Lock test".into(),
        })
        .await
        .expect("user");
    let session = tx
        .sessions()
        .insert(&InsertSession {
            id: SessionId::new(),
            user_id,
            authentication_methods: vec![AuthenticationMethod::Passkey],
            authenticated_at: now,
            expires_at: now + Duration::seconds(1),
            user_agent_family: None,
            passkey_confirmed_at: Some(now),
        })
        .await
        .expect("session");
    tx.commit().await.expect("commit");
    let mut holder = database.begin().await.expect("holder transaction");
    holder
        .users()
        .find_active_by_id_for_update(user_id)
        .await
        .expect("account lock")
        .expect("active account");
    let change = tokio::spawn({
        let database = database.clone();
        async move {
            let mut change = database.begin().await.expect("change transaction");
            Confirmed::<CONFIRMATION_MAX_AGE>(session)
                .lock(&mut change)
                .await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    holder.rollback().await.expect("release account");
    assert!(matches!(
        change.await.expect("change task"),
        Err(SessionError::Missing)
    ));
}
