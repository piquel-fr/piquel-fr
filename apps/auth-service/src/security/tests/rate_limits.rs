//! Rate-limit budgets: which routes spend them, how they are shared and bounded.

use super::*;
use crate::routes::{audit, federation, passkey};
use crate::tests::Replicas;

/// The request deadline also bounds waiting for a locked rate-limit bucket.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rate_limit_deadline_includes_a_blocked_database_query() {
    let mut fixture = SecurityFixture::new().await;
    let bucket = Digest::sha256(format!("token:{}", fixture.peer.ip()).as_bytes());
    let mut transaction = fixture.policy.database.begin().await.expect("transaction");
    transaction
        .security()
        .allow_request(bucket.as_bytes(), 120, std::time::Duration::from_mins(1))
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
/// Unknown paths do not drain budgets. Each budget is spent on its own: exhausted
/// reads get a retry delay and exhausted token requests are refused, while sign-in
/// and the account stay available.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn budgets_are_separate_and_unknown_paths_do_not_consume_them() {
    let fixture = SecurityFixture::new().await;
    for _ in 0..REQUESTS_PER_MINUTE + 5 {
        assert_eq!(
            fixture
                .request(Method::GET, "/login/nonexistent", None, false)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
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
    assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    // UserInfo calls never block code exchanges.
    assert_eq!(
        fixture
            .request(Method::POST, "/oauth/token", None, false)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let bucket = Digest::sha256(format!("token:{}", fixture.peer.ip()).as_bytes());
    for _ in 0..REQUESTS_PER_MINUTE {
        fixture
            .policy
            .database
            .security()
            .allow_request(
                bucket.as_bytes(),
                REQUESTS_PER_MINUTE,
                std::time::Duration::from_mins(1),
            )
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
    for (method, path, origin, csrf) in [
        (
            Method::POST,
            "/webauthn/authenticate/start",
            Some("https://auth.piquel.fr"),
            true,
        ),
        (Method::GET, passkey::LIST, None, false),
    ] {
        assert_eq!(
            fixture.request(method, path, origin, csrf).await.status(),
            StatusCode::ACCEPTED,
            "{path}"
        );
    }
}

/// One client's budget is shared across replicas: alternating between them, the
/// request after the budget is still rejected.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn replicas_share_one_budget() {
    let replicas = Replicas::new().await;
    let status = async |router: &Router| {
        let request = HttpRequest::get(passkey::LIST)
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
            .allow_request(bucket.as_bytes(), 120, std::time::Duration::from_mins(1))
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
        (audit::CHECKPOINTS, Some(RateCategory::Audit)),
        (audit::LATEST_CHECKPOINT, Some(RateCategory::Audit)),
        (oidc::TOKEN, Some(RateCategory::Token)),
        (oidc::PAR, Some(RateCategory::Token)),
        (oidc::USERINFO, Some(RateCategory::UserInfo)),
        (oidc::LOGOUT, Some(RateCategory::Login)),
        (oidc::AUTHORIZE, Some(RateCategory::Login)),
        (oidc::AUTHORIZE_RESUME, Some(RateCategory::Login)),
        (passkey::LIST, Some(RateCategory::Account)),
        (federation::IDENTITIES, Some(RateCategory::Account)),
        (passkey::AUTHENTICATE_START, Some(RateCategory::Login)),
        (federation::CALLBACK, Some(RateCategory::Login)),
    ] {
        assert_eq!(Endpoint::classify(path).rate_category(), budget, "{path}");
    }
    // The root and a page's path ending in a slash only redirect to a page.
    let redirects = page::ALL.map(|path| format!("{path}/"));
    for path in page::ALL
        .into_iter()
        .chain([page::ROOT])
        .chain(redirects.iter().map(String::as_str))
    {
        assert_eq!(
            Endpoint::classify(path).rate_category(),
            Some(RateCategory::Page),
            "{path}"
        );
    }
}

/// A request is classified by the route it matched, so the pages of an app, whose
/// path names it, and their twins ending in a slash are pages. A request no route
/// matched is classified by its path.
#[tokio::test]
async fn requests_are_classified_by_their_route() {
    // Answers whether the request is a page's.
    let classified = || {
        any(|request: Request| async move {
            if Endpoint::of(&request).rate_category() == Some(RateCategory::Page) {
                StatusCode::ACCEPTED
            } else {
                StatusCode::NO_CONTENT
            }
        })
    };
    let router = page::ALL
        .into_iter()
        .fold(Router::new(), |router, path| {
            router
                .route(path, classified())
                .route(&format!("{path}/"), classified())
        })
        .fallback(classified());
    for (path, status) in [
        ("/developers/clients/c_any", StatusCode::ACCEPTED),
        ("/developers/clients/c_any/settings", StatusCode::ACCEPTED),
        ("/developers/clients/c_any/secrets/", StatusCode::ACCEPTED),
        (
            "/developers/clients/c_any/elsewhere",
            StatusCode::NO_CONTENT,
        ),
    ] {
        let request = HttpRequest::get(path).body(Body::empty()).expect("request");
        let response = router.clone().oneshot(request).await.expect("response");
        assert_eq!(response.status(), status, "{path}");
    }
}
