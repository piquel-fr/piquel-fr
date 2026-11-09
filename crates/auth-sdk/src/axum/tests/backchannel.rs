//! Back-channel logout: a route only for an app that handles it, which hands the
//! handler each valid logout token.

use super::*;
use crate::{LogoutScope, SessionId};
use chrono::TimeDelta;
use sourceorigin_common::{
    DeliveryId,
    protocol::claims::{Absent, Audience, LogoutEvents, LogoutTokenClaims},
};

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

/// What a handler failed with.
#[derive(Debug, thiserror::Error)]
#[error("the app's database is down")]
struct Down;

/// An app with no handler has no route. With one, the handler gets every valid
/// token, by `sid` or by `sub` alone, and the route answers 200 once it succeeds and
/// 500 when it fails, so auth retries; an invalid token never reaches it.
#[tokio::test]
async fn backchannel_logout_hands_tokens_to_the_handler() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let issuer = endpoint.issuer(&clock());
    let response = post_logout(
        &login_app(&issuer),
        format!("logout_token={}", logout(Some(USER), None)),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "no handler, no route"
    );

    let received = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let app = login_app_with(&issuer, |routes| {
        let (received, fail) = (received.clone(), fail.clone());
        routes.on_backchannel_logout(move |token: crate::LogoutToken| {
            let failing = fail.load(Ordering::SeqCst);
            if !failing {
                received
                    .lock()
                    .expect("received")
                    .push(token.scope().clone());
            }
            async move { if failing { Err(Down) } else { Ok(()) } }
        })
    });
    let sid = SessionId::new();
    let by_session = logout(Some(USER), Some(sid));
    // Auth delivers again when it lost the answer: the handler sees it twice.
    for body in [&by_session, &by_session, &logout(Some(USER), None)] {
        let response = post_logout(&app, format!("logout_token={body}")).await;
        assert_eq!(status(&response), (StatusCode::OK, Some("no-store")));
    }
    assert_eq!(
        *received.lock().expect("received"),
        [
            LogoutScope::Session(sid),
            LogoutScope::Session(sid),
            LogoutScope::Subject(USER.into())
        ]
    );

    fail.store(true, Ordering::SeqCst);
    let response = post_logout(&app, format!("logout_token={}", logout(None, Some(sid)))).await;
    assert_eq!(
        status(&response),
        (StatusCode::INTERNAL_SERVER_ERROR, Some("no-store"))
    );

    fail.store(false, Ordering::SeqCst);
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
    assert_eq!(received.lock().expect("received").len(), 3, "never handled");
}
