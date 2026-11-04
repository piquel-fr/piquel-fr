//! Refreshing under the lease, and which failures end the session.

use super::*;

/// Two requests with an expired access token make one refresh and both succeed, and
/// a logout during a refresh leaves the session deleted.
#[tokio::test]
async fn refreshes_are_serialized() {
    let backend = MemoryBackend::default();
    let endpoint = TokenEndpoint::start(Duration::from_millis(300)).await;
    let issuer = issuer_with_token_endpoint(endpoint.url.clone());
    let (app, _) = login_app(&issuer, &backend);
    let login = stored_login(USER, SessionId::new(), -60);
    let (key, cookie) = session(&backend, &login).await;
    let headers = [(header::COOKIE, cookie.as_str())];
    let (first, second) =
        tokio::join!(get_with(&app, "/", &headers), get_with(&app, "/", &headers));
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(text(first).await, "access-1");
    assert_eq!(text(second).await, "access-1");
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1, "one refresh");
    let stored = load(&backend, &key).await.expect("session");
    // Inserted at 1, leased at 2, saved at 3.
    assert_eq!((stored.version, stored.leased), (3, false));
    assert_eq!(
        stored
            .login
            .refresh_token()
            .map(crate::RefreshToken::expose),
        Some("refresh-1")
    );

    let (key, cookie) = session(&backend, &login).await;
    let refreshing = tokio::spawn({
        let app = app.clone();
        async move { get_with(&app, "/", &[(header::COOKIE, &cookie)]).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    sessions(backend.clone())
        .delete(&key)
        .await
        .expect("logout");
    let response = refreshing.await.expect("request");
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "signed out");
    assert!(load(&backend, &key).await.is_none(), "not resurrected");
}

/// A refused grant ends the session, as does a refresh whose outcome is unknown,
/// since auth may have rotated the token. An error answer from auth keeps it, and so
/// does a refresh that could not even connect.
#[tokio::test]
async fn refresh_failures_end_sessions_only_when_the_token_may_be_spent() {
    let unreachable: Url = "http://127.0.0.1:9/token".parse().expect("URL");
    // Accepts the request, then hangs up without answering.
    let hangup = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let silent: Url = format!("http://{}/token", hangup.local_addr().expect("address"))
        .parse()
        .expect("URL");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = hangup.accept().await {
            let mut request = [0; 4096];
            let _read = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
        }
    });
    let failing = |status, error| async move { TokenEndpoint::failing(status, error).await.url };
    for (endpoint, kept) in [
        (
            failing(StatusCode::INTERNAL_SERVER_ERROR, "server_error").await,
            true,
        ),
        (
            failing(StatusCode::BAD_REQUEST, "invalid_client").await,
            true,
        ),
        (
            failing(StatusCode::BAD_REQUEST, "invalid_grant").await,
            false,
        ),
        (unreachable, true),
        (silent, false),
    ] {
        let backend = MemoryBackend::default();
        let (app, _) = login_app(&issuer_with_token_endpoint(endpoint.clone()), &backend);
        let (key, cookie) = session(&backend, &stored_login(USER, SessionId::new(), -60)).await;
        let response = get_with(&app, "/", &[(header::COOKIE, &cookie)]).await;
        let stored = load(&backend, &key).await;
        assert_eq!(stored.is_some(), kept, "{endpoint}");
        let expected = if kept {
            StatusCode::OK
        } else {
            StatusCode::SEE_OTHER
        };
        assert_eq!(response.status(), expected, "{endpoint}");
        if let Some(stored) = stored {
            // The lease was given back, so the next request may refresh again.
            assert!(!stored.leased, "{endpoint}");
        }
    }
}
