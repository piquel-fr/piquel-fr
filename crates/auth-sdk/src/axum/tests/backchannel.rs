//! Back-channel logout.

use super::*;

/// A logout token for `sub` and `sid`, valid now, with a fresh `jti`.
fn logout(sub: Option<&str>, sid: Option<SessionId>) -> String {
    let now = Utc::now();
    let claims = LogoutTokenClaims {
        iss: "https://auth.example.com".into(),
        aud: Audience::One(CLIENT.into()),
        iat: now,
        exp: now + TimeDelta::minutes(2),
        jti: DeliveryId::new(),
        sub: sub.map(str::to_owned),
        sid,
        events: LogoutEvents,
        nonce: Absent,
    };
    sign(&serde_json::to_value(claims).expect("claims"), "logout+jwt")
}

/// Posts `body` to the back-channel logout route as a form.
async fn post_logout(app: &Router, body: String) -> Response {
    let request = Request::post("/auth/backchannel-logout")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("request");
    app.clone().oneshot(request).await.expect("response")
}

/// The response's status and `Cache-Control`.
fn status(response: &Response) -> (StatusCode, Option<&str>) {
    let cache = response.headers().get(header::CACHE_CONTROL);
    (
        response.status(),
        cache.map(|value| value.to_str().expect("text")),
    )
}

/// A logout by `sid` ends the sessions of that auth session only, and a logout by
/// `sub` alone ends every session of that user. A token sent again, as auth does
/// when it lost the answer, is answered 200 and ends no session started since.
#[tokio::test]
async fn backchannel_logout_ends_the_named_sessions() {
    let backend = MemoryBackend::default();
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    let (app, _) = login_app(&issuer, &backend);
    let other = "01936f3e-8c00-7000-8000-000000000009";
    let ended = SessionId::new();
    let (first, _) = session(&backend, &stored_login(USER, ended, 300)).await;
    let (second, _) = session(&backend, &stored_login(USER, SessionId::new(), 300)).await;
    let (stranger, _) = session(&backend, &stored_login(other, SessionId::new(), 300)).await;

    let response = post_logout(
        &app,
        format!("logout_token={}", logout(Some(USER), Some(ended))),
    )
    .await;
    assert_eq!(status(&response), (StatusCode::OK, Some("no-store")));
    assert!(load(&backend, &first).await.is_none());
    assert!(
        load(&backend, &second).await.is_some(),
        "another auth session"
    );

    let by_user = format!("logout_token={}", logout(Some(USER), None));
    let response = post_logout(&app, by_user.clone()).await;
    assert_eq!(status(&response), (StatusCode::OK, Some("no-store")));
    assert!(load(&backend, &second).await.is_none());
    assert!(load(&backend, &stranger).await.is_some(), "another user");

    let (third, _) = session(&backend, &stored_login(USER, SessionId::new(), 300)).await;
    let again = post_logout(&app, by_user).await;
    assert_eq!(status(&again), (StatusCode::OK, Some("no-store")));
    assert!(
        load(&backend, &third).await.is_some(),
        "a sign-in after the logout"
    );
}

/// An invalid token, or none, is refused with the OAuth error and `no-store`.
#[tokio::test]
async fn backchannel_logout_refuses_bad_tokens() {
    let backend = MemoryBackend::default();
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    let (app, _) = login_app(&issuer, &backend);
    let id_token = format!("logout_token={}", vector_token("id-valid"));
    for body in [id_token, "token=abc".to_owned()] {
        let response = post_logout(&app, body.clone()).await;
        assert_eq!(
            status(&response),
            (StatusCode::BAD_REQUEST, Some("no-store")),
            "{body}"
        );
        assert_eq!(text(response).await, r#"{"error":"invalid_request"}"#);
    }
}

/// A sign-in that completes after auth ended its session keeps no session, while
/// the user's other sign-ins still start.
#[tokio::test]
async fn sign_ins_cannot_join_an_ended_session() {
    let backend = MemoryBackend::default();
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    let (app, _) = login_app(&issuer, &backend);
    let ended = SessionId::new();
    let token = logout(Some(USER), Some(ended));
    let response = post_logout(&app, format!("logout_token={token}")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let key = SessionKey::generate().expect("key");
    let started = sessions(backend.clone())
        .insert(
            &key,
            &stored_login(USER, ended, 300),
            Utc::now() + TimeDelta::hours(1),
            Utc::now(),
        )
        .await
        .expect("insert");
    assert!(!started);
    assert!(load(&backend, &key).await.is_none());
    session(&backend, &stored_login(USER, SessionId::new(), 300)).await;
}
