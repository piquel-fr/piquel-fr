//! The session cookie: the shared vectors, refresh without a lease, how a refresh
//! failure ends a session, logout, and the cookie's size.

use super::*;
use crate::{
    BearerToken, IdToken, RefreshToken, Tokens,
    axum::login::{SessionCookie, SessionCookieError},
};
use ::axum::http::HeaderMap;
use chrono::TimeDelta;

/// The session a `Cookie` header holds is the one the vectors expect, read back in
/// the shape they write, or none.
#[tokio::test]
async fn session_cookie_vectors() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    for case in Case::all("sessions") {
        let client = endpoint.issuer(&case.clock()).client(ClientConfig {
            client_id: case.text("client_id").parse().expect("client ID"),
            credentials: Credentials::Secret("secret".to_owned().into()),
            redirect_uri: "https://notes.example.com/auth/callback"
                .parse()
                .expect("callback"),
        });
        let key = CookieKey::parse(case.text("cookie_key")).expect("cookie key");
        let routes = LoginRoutes::new(client, key).expect("a confidential client");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            case.text("cookie").parse().expect("cookie header"),
        );
        let session = match routes.0.open_session(&headers) {
            SessionCookie::Open(login) => serde_json::to_value(&login.0).expect("session"),
            SessionCookie::Ended | SessionCookie::Absent => serde_json::Value::Null,
        };
        assert_eq!(session, case.json["expected"]["ok"], "{}", case.name);
    }
}

/// A cookie key holds the bytes the vectors expect, whichever encoding it is written
/// in, or is refused as they expect: with the length it holds, if it is in an
/// encoding.
#[test]
fn cookie_key_vectors() {
    for case in Case::all("cookie-keys") {
        let parsed = CookieKey::parse(case.text("cookie_key"));
        let expected = &case.json["expected"];
        let Some(hex) = expected["ok"].as_str() else {
            let refusal = match parsed {
                Err(CookieKeyError::WrongLength(bytes)) => {
                    serde_json::json!({ "code": "wrong_length", "bytes": bytes })
                }
                Err(CookieKeyError::Unrecognized) => serde_json::json!({ "code": "unrecognized" }),
                other => panic!("{}: {other:?}", case.name),
            };
            assert_eq!(refusal, expected["error"], "{}", case.name);
            continue;
        };
        let secret: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
            .collect();
        // The same bytes derive the same keys: one opens what the other sealed.
        let sealed = parsed
            .expect(&case.name)
            .session
            .seal(&"value", "context")
            .expect("seal");
        let expected = CookieKey::from_secret(&secret).expect("cookie key");
        assert_eq!(
            expected
                .session
                .open::<String>(&sealed, "context")
                .as_deref(),
            Some("value"),
            "{}",
            case.name
        );
    }
}

/// The app's home page for the browser holding `session`: its status, the access
/// token it shows, and the session cookie the response sets, if any.
async fn home(app: &Router, session: &str) -> (StatusCode, String, Option<String>) {
    let response = get_with(app, "/", &[(header::COOKIE, session)]).await;
    let cookie = set_cookie(&response, SESSION_COOKIE);
    if cookie.is_some() {
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    (response.status(), text(response).await, cookie)
}

/// Two requests that both find the access token expired both refresh, with no lease
/// between them, and both succeed: a confidential client's refresh token does not
/// rotate. Each response carries its new session, and a request that reads the
/// session twice refreshes once.
#[tokio::test]
async fn concurrent_refreshes_all_succeed() {
    let endpoint = TokenEndpoint::start(Duration::from_millis(100)).await;
    let clock = clock();
    let app = login_app(&endpoint.issuer(&clock));
    let session = sign_in(&app, USER).await;
    assert_eq!(
        home(&app, &session).await,
        (StatusCode::OK, "access-0".into(), None)
    );

    clock.advance(300);
    let (first, second) = tokio::join!(home(&app, &session), home(&app, &session));
    assert_eq!((first.0, second.0), (StatusCode::OK, StatusCode::OK));
    let mut tokens = [first.1.clone(), second.1];
    tokens.sort();
    assert_eq!(tokens, ["access-1", "access-2"]);
    assert_eq!(endpoint.refreshes.load(Ordering::SeqCst), 2);
    let refreshed = first.2.expect("the refreshed session");
    assert_eq!(
        home(&app, &refreshed).await,
        (StatusCode::OK, first.1, None)
    );

    let response = get_with(&app, "/both", &[(header::COOKIE, &session)]).await;
    assert_eq!(text(response).await, "access-3 access-3");
    assert_eq!(endpoint.refreshes.load(Ordering::SeqCst), 3, "one refresh");
}

/// Auth's refusal of the refresh token ends the session and clears its cookie. Any
/// other failure spends nothing: the session goes on with its access token while
/// that is valid, and once it expired the request is refused with 503, keeping the
/// cookie for a later refresh, so a session auth ended never outlives its token.
#[tokio::test]
async fn refresh_failures_end_the_session_only_when_auth_refuses() {
    /// The home page, `seconds` after signing in at `endpoint`.
    async fn after(endpoint: &TokenEndpoint, seconds: i64) -> Response {
        let clock = clock();
        let app = login_app(&endpoint.issuer(&clock));
        let session = sign_in(&app, USER).await;
        clock.advance(seconds);
        get_with(&app, "/", &[(header::COOKIE, &session)]).await
    }
    let refused = TokenEndpoint::refusing(StatusCode::BAD_REQUEST, "invalid_grant").await;
    let response = after(&refused, 280).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "signed out");
    assert_eq!(
        set_cookie(&response, SESSION_COOKIE),
        Some(format!("{SESSION_COOKIE}="))
    );
    for status in [StatusCode::BAD_REQUEST, StatusCode::SERVICE_UNAVAILABLE] {
        let failing = TokenEndpoint::refusing(status, "temporarily_unavailable").await;
        let response = after(&failing, 280).await;
        assert_eq!(response.status(), StatusCode::OK, "{status}");
        assert_eq!(set_cookie(&response, SESSION_COOKIE), None, "{status}");
        assert_eq!(text(response).await, "access-0");
        let response = after(&failing, 300).await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{status}"
        );
        assert_eq!(set_cookie(&response, SESSION_COOKIE), None, "{status}");
    }
}

/// A cookie that does not open, or whose session ended, is no session, and the
/// response clears it.
#[tokio::test]
async fn ended_sessions_are_cleared() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let clock = clock();
    let app = login_app(&endpoint.issuer(&clock));
    let session = sign_in(&app, USER).await;
    let other_app = sign_in(&login_app(&endpoint.issuer(&clock)), USER).await;
    clock.advance(TimeDelta::hours(12).num_seconds());
    for cookie in [session, other_app] {
        let response = get_with(&app, "/", &[(header::COOKIE, &cookie)]).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            set_cookie(&response, SESSION_COOKIE),
            Some(format!("{SESSION_COOKIE}="))
        );
    }
}

/// Logout revokes the session's refresh token at auth, so no copy of the cookie
/// refreshes again, clears the cookie, and sends the browser to auth's logout with
/// the client, there being no ID token to hint with. If auth cannot revoke it, the
/// cookie stays, for the user to try again.
#[tokio::test]
async fn logout_revokes_the_refresh_token() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let app = login_app(&endpoint.issuer(&clock()));
    let session = sign_in(&app, USER).await;
    let logout = || async {
        let request = Request::post("/auth/logout")
            .header(header::COOKIE, &session)
            .header(header::ORIGIN, "https://notes.example.com")
            .body(Body::empty())
            .expect("request");
        app.clone().oneshot(request).await.expect("response")
    };
    endpoint.revocations_fail.store(true, Ordering::SeqCst);
    let response = logout().await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(set_cookies(&response), Vec::<String>::new());

    endpoint.revocations_fail.store(false, Ordering::SeqCst);
    let response = logout().await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        *endpoint.revoked.lock().expect("revocations"),
        ["refresh-0"]
    );
    assert_eq!(
        set_cookie(&response, SESSION_COOKIE),
        Some(format!("{SESSION_COOKIE}="))
    );
    let location: Url = response.headers()[header::LOCATION]
        .to_str()
        .expect("location")
        .parse()
        .expect("logout URL");
    let query: Vec<_> = location
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    assert_eq!(query, ["client_id"]);
}

/// A sign-in replacing the browser's session revokes that session's refresh token,
/// so no copy of the old cookie outlives its access token. If auth cannot revoke it,
/// the sign-in fails with 502 once its code is redeemed: the new grant is revoked,
/// no new session is set, and the old cookie stays, still renewable, so the user can
/// sign in again.
#[tokio::test]
async fn sign_ins_revoke_the_session_they_replace() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let clock = clock();
    let app = login_app(&endpoint.issuer(&clock));
    let first = sign_in(&app, USER).await;
    let replace = async || {
        let login = Started::at(&app, "%2F", &[]).await;
        login
            .complete(&app, USER, &[login.cookie.clone(), first.clone()])
            .await
    };
    endpoint
        .refused
        .lock()
        .expect("refused")
        .push("refresh-0".into());
    let response = replace().await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        set_cookie(&response, SESSION_COOKIE),
        None,
        "no new session, and the old one stays"
    );
    assert_eq!(
        *endpoint.revoked.lock().expect("revocations"),
        ["refresh-1"],
        "the new grant is revoked"
    );
    clock.advance(300);
    let (status, shown, _) = home(&app, &first).await;
    assert_eq!((status, shown.as_str()), (StatusCode::OK, "access-1"));

    endpoint.refused.lock().expect("refused").clear();
    let response = replace().await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        *endpoint.revoked.lock().expect("revocations"),
        ["refresh-1", "refresh-0"]
    );
}

/// A session whose end comes while its refresh runs is over: the request has no
/// session, and the response clears the cookie.
#[tokio::test]
async fn sessions_end_on_time_even_mid_refresh() {
    let clock = clock();
    let during = clock.clone();
    let endpoint = TokenEndpoint::refreshing(move |call| {
        // The refresh takes ten seconds.
        during.advance(10);
        async move { ::axum::Json(TokenEndpoint::tokens(&format!("access-{call}"))).into_response() }
    })
    .await;
    let app = login_app(&endpoint.issuer(&clock));
    let session = sign_in(&app, USER).await;
    clock.advance(TimeDelta::hours(12).num_seconds() - 5);
    let response = get_with(&app, "/", &[(header::COOKIE, &session)]).await;
    assert_eq!(endpoint.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        set_cookie(&response, SESSION_COOKIE),
        Some(format!("{SESSION_COOKIE}="))
    );
}

/// Tokens of a sign-in for the vectors' user whose access token is `access_bytes`
/// long and whose name and email are as long as auth allows, in 4-byte characters.
fn worst_case_tokens(access_bytes: usize) -> Tokens {
    let mut claims = token_case("id-valid").json["expected"]["ok"].clone();
    claims["name"] = json!("😀".repeat(80));
    claims["email"] = json!(format!("{}@example.com", "e".repeat(242)));
    claims["email_verified"] = json!(true);
    claims["preferred_username"] = json!("u".repeat(32));
    claims["profile_version"] = json!(u32::MAX);
    Tokens {
        id_token: Some(IdToken::unchecked(
            serde_json::from_value(claims).expect("claims"),
            "",
        )),
        access_token: BearerToken::new("a".repeat(access_bytes)),
        expires_at: Utc::now() + TimeDelta::minutes(5),
        scopes: "email offline_access openid profile"
            .parse()
            .expect("scopes"),
        refresh_token: Some(RefreshToken::new(format!(
            "prt_{}.{}",
            USER,
            "s".repeat(43)
        ))),
    }
}

/// A worst-case session fits in a cookie once access tokens carry no profile (#279),
/// as the 1,227-byte token of a 3072-bit key, 64-byte client and resource IDs, and
/// today's other claims make; a larger one fails rather than set a cookie the browser
/// would drop.
#[tokio::test]
async fn sessions_fit_in_a_cookie() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let routes = LoginRoutes::new(
        client(&endpoint.issuer(&clock())),
        CookieKey::generate().expect("cookie key"),
    )
    .expect("a confidential client");
    let ends_at = Utc::now() + TimeDelta::hours(12);
    let minimal = StoredLogin::new(worst_case_tokens(1227), ends_at).expect("a session");
    let cookie = routes.0.session_cookie(&minimal).expect("fits");
    let pair = cookie
        .to_str()
        .expect("text")
        .split(';')
        .next()
        .expect("pair");
    assert!(pair.len() <= 4096, "{}", pair.len());
    let today = StoredLogin::new(worst_case_tokens(2272), ends_at).expect("a session");
    assert!(matches!(
        routes.0.session_cookie(&today),
        Err(SessionCookieError::TooLarge(_))
    ));
}

/// Without a refresh token, a session cannot learn that auth ended it, so it ends
/// with its access token.
#[test]
fn sessions_without_a_refresh_token_end_with_their_access_token() {
    let mut tokens = worst_case_tokens(100);
    tokens.refresh_token = None;
    let expires_at = tokens.expires_at;
    let login = StoredLogin::new(tokens, Utc::now() + TimeDelta::hours(12)).expect("a session");
    assert_eq!(login.ends_at(), expires_at);
}

/// A revocation auth never answers gives up after the SDK's deadline, whatever the
/// HTTP client's own timeout: logout answers 502 keeping the cookie, and a sign-in
/// replacing the session answers 502 too, so neither hangs.
#[tokio::test]
async fn revocations_give_up_after_their_deadline() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    // An injected client without a timeout of its own.
    let http = Http::plain(reqwest::Client::builder());
    let app = login_app(&endpoint.issuer_with(&clock(), http));
    let session = sign_in(&app, USER).await;
    endpoint.revocations_hang.store(true, Ordering::SeqCst);
    // Waiting out the hour the revocation hangs takes no time, but the deadline
    // must end it first.
    tokio::time::pause();
    let logout = Request::post("/auth/logout")
        .header(header::COOKIE, &session)
        .header(header::ORIGIN, "https://notes.example.com")
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(logout).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(set_cookies(&response), Vec::<String>::new());

    let login = Started::at(&app, "%2F", std::slice::from_ref(&session)).await;
    let both = [login.cookie.clone(), session];
    let response = login.complete(&app, USER, &both).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(set_cookie(&response, SESSION_COOKIE), None);
    assert!(endpoint.revoked.lock().expect("revocations").is_empty());
    // The logout's, the replaced session's and then the refused new grant's revocations
    // all reached the hanging endpoint, so the deadline, not an early error, ended them.
    assert_eq!(endpoint.revocations_received.load(Ordering::SeqCst), 3);
}

/// A change to an ID token's claims.
type ClaimChange = fn(&mut serde_json::Value);

/// Serves endpoints whose refreshes return an ID token for [`USER`], with `nonce`
/// for the `n`th refresh when `nonce(n)` gives one, and `change` applied.
async fn refreshing_id_tokens(
    nonce: impl Fn(usize) -> Option<String> + Clone + Send + Sync + 'static,
    change: ClaimChange,
) -> TokenEndpoint {
    TokenEndpoint::refreshing(move |call| {
        let nonce = nonce.clone();
        async move {
            let mut claims = id_claims(USER);
            if let Some(nonce) = nonce(call) {
                claims["nonce"] = json!(nonce);
            }
            change(&mut claims);
            let mut tokens = TokenEndpoint::tokens(&format!("access-{call}"));
            tokens["id_token"] = json!(sign(&claims, TokenType::Id));
            ::axum::Json(tokens).into_response()
        }
    })
    .await
}

/// A refresh whose ID token changes the sign-in ends the session and clears its
/// cookie (OIDC Core §12.2): another user, `auth_time` or `acr`, or a `nonce` the
/// sign-in did not send. One carrying them over is kept.
#[tokio::test]
async fn refreshes_keep_the_original_sign_in() {
    let changes: [(&str, ClaimChange); 5] = [
        ("unchanged", |_| {}),
        ("another user", |claims| {
            claims["sub"] = json!("01936f3e-8c00-7000-8000-000000000009");
        }),
        ("a later auth_time", |claims| {
            claims["auth_time"] = json!(claims["auth_time"].as_i64().expect("auth_time") + 60);
        }),
        ("another acr", |claims| {
            claims["acr"] = json!("urn:sourceorigin:acr:social");
        }),
        ("a nonce", |claims| claims["nonce"] = json!("replayed")),
    ];
    for (change, apply) in changes {
        let endpoint = refreshing_id_tokens(|_| None, apply).await;
        let clock = clock();
        let app = login_app(&endpoint.issuer(&clock));
        let session = sign_in(&app, USER).await;
        clock.advance(300);
        let (status, shown, cookie) = home(&app, &session).await;
        if change == "unchanged" {
            assert_eq!((status, shown.as_str()), (StatusCode::OK, "access-1"));
        } else {
            assert_eq!(status, StatusCode::SEE_OTHER, "{change}");
            assert_eq!(cookie, Some(format!("{SESSION_COOKIE}=")), "{change}");
        }
    }
}

/// A refresh's `nonce` is checked against the sign-in's, which the session keeps
/// even after a refresh that returned none: one sending it again keeps the session,
/// and one sending another ends it.
#[tokio::test]
async fn refresh_nonces_match_the_sign_in() {
    for kept in [true, false] {
        let signed_in = Arc::new(Mutex::new(String::new()));
        let nonce = {
            let signed_in = signed_in.clone();
            move |call| match call {
                1 => None,
                _ if kept => Some(signed_in.lock().expect("nonce").clone()),
                _ => Some("another".to_owned()),
            }
        };
        let endpoint = refreshing_id_tokens(nonce, |_| {}).await;
        let clock = clock();
        let app = login_app(&endpoint.issuer(&clock));
        let login = Started::at(&app, "%2F", &[]).await;
        signed_in.lock().expect("nonce").clone_from(&login.nonce);
        let response = login
            .complete(&app, USER, std::slice::from_ref(&login.cookie))
            .await;
        let session = set_cookie(&response, SESSION_COOKIE).expect("a session");
        clock.advance(300);
        let (_, shown, cookie) = home(&app, &session).await;
        assert_eq!(shown, "access-1");
        clock.advance(300);
        let (status, _, cookie) = home(&app, &cookie.expect("the refreshed session")).await;
        if kept {
            assert_eq!(status, StatusCode::OK);
        } else {
            assert_eq!(status, StatusCode::SEE_OTHER);
            assert_eq!(cookie, Some(format!("{SESSION_COOKIE}=")));
        }
    }
}
