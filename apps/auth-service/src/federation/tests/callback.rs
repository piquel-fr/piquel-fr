//! The provider callback: strict return destinations and browser bindings, pending
//! evidence for unregistered subjects, and failed or cancelled authorizations.

use super::*;

/// Accepts auth paths only, and rejects duplicated pending-browser cookies.
#[test]
fn return_destinations_and_browser_bindings_are_strict() {
    for value in [
        "//evil.test",
        "/\\evil.test",
        "https://evil.test",
        "https://auth.piquel.fr/settings",
        "/login#x",
        "/\n/evil",
        "settings",
        "javascript:alert(1)",
        "https:\\\\evil.test",
    ] {
        assert!(ReturnTo::parse(Some(value)).is_err(), "{value}");
    }
    let path = "/oauth/authorize?request=abc";
    assert_eq!(ReturnTo::parse(Some(path)).expect(path).0, path);
    assert_eq!(
        ReturnTo::parse(None).expect("default return").0,
        DEFAULT_RETURN_TO
    );
    assert!(ReturnTo::parse(Some(&format!("/{}", "x".repeat(MAX_RETURN_TO_BYTES)))).is_err());
    let secret = Secret::generate().expect("browser secret");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{0}={1}; {0}={1}",
            BrowserCookie::FederationPending.as_str(),
            secret.encoded()
        ))
        .expect("cookie"),
    );
    assert!(BrowserCookie::FederationPending.read(&headers).is_none());
}

/// Callbacks require browser state and retain unregistered subjects as pending evidence.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn provider_mock_callback_requires_browser_state_and_stays_pending() {
    let test = TestApp::new().await;
    let router = test.routes();
    let (state, cookie) = test.start(DEFAULT_RETURN_TO).await;
    let path = format!("/login/github/callback?code=mock-code&state={state}");
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::GET,
            &path,
            None,
            &serde_json::Value::Null,
        ))
        .await
        .expect("unbound callback");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::GET,
            &path,
            Some(&cookie),
            &serde_json::Value::Null,
        ))
        .await
        .expect("callback");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login?social=signup");
    assert!(
        !response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value
                .to_str()
                .expect("cookie")
                .starts_with("__Host-piquel_session="))
    );
    let response = router
        .oneshot(TestApp::request(
            Method::GET,
            &path,
            Some(&cookie),
            &serde_json::Value::Null,
        ))
        .await
        .expect("replay");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Cancelled or failed authorization preserves the original continuation and consumes state.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn failed_provider_preserves_stored_continuation_and_consumes_state() {
    let mut test = TestApp::new().await;
    test.app
        .endpoints
        .get_mut(&Provider::GitHub)
        .expect("GitHub facts")
        .token
        .push_str("/missing");
    let router = test.routes();
    let destination = "/oauth/authorize/resume?transaction=trusted-transaction";
    for (callback_query, error) in [
        ("error=access_denied", "social_cancelled"),
        ("code=invalid", "social_failed"),
        ("code=", "social_failed"),
        ("", "social_failed"),
    ] {
        let (state, cookie) = test.start(destination).await;
        let path = format!(
            "/login/github/callback?{callback_query}&state={state}&return_to=https://evil.example"
        );
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::GET,
                &path,
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("cancel");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let target = Url::parse(
            response.headers()[header::LOCATION]
                .to_str()
                .expect("location"),
        )
        .expect("target");
        assert_eq!(target.origin(), test.app.origin.as_url().origin());
        assert!(
            target
                .query_pairs()
                .any(|(key, value)| key == "return_to" && value == destination)
        );
        assert!(
            target
                .query_pairs()
                .any(|(key, value)| key == "error" && value == error)
        );
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::GET,
                &path,
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("replay");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
