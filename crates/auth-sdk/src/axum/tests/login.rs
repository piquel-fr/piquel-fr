//! Login's redirects, `return_to`, pending logins, and the origin checks on logout
//! and the session extractors.

use super::*;

/// `return_to` accepts only same-origin relative paths.
#[test]
fn return_to_refuses_open_redirects() {
    for path in ["/", "/notes?page=2", "/a/b"] {
        assert!(path.parse::<ReturnTo>().is_ok(), "{path}");
    }
    for path in [
        "",
        "notes",
        "//evil.example",
        "/\\evil.example",
        "https://evil.example/",
        "/notes#x",
        "/a\\b",
        "/a\nb",
    ] {
        assert!(path.parse::<ReturnTo>().is_err(), "{path:?}");
    }
}

/// A public client's refresh token rotates, so every copy of a session cookie could
/// not redeem it: the login routes take confidential clients only.
#[tokio::test]
async fn login_routes_refuse_public_clients() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let public = endpoint.issuer(&clock()).client(ClientConfig {
        client_id: CLIENT.parse().expect("client ID"),
        credentials: Credentials::None,
        redirect_uri: "https://notes.example.com/auth/callback"
            .parse()
            .expect("callback"),
    });
    let key = CookieKey::generate().expect("cookie key");
    assert!(matches!(LoginRoutes::new(public, key), Err(PublicClient)));
}

/// Without a session, a browser navigating to a page is redirected through login and
/// back to its full path, prefix included when it sits in a nested router. Anything
/// else, a `fetch` or a client sending no fetch metadata, gets 401: following the
/// redirect to auth would fail its CORS check.
#[tokio::test]
async fn signed_in_redirects_only_navigations() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let app = login_app(&endpoint.issuer(&clock()));
    let response = get_with(&app, "/app/notes?page=2", &[]).await;
    assert_eq!(
        response.headers()[header::LOCATION],
        "/auth/login?return_to=%2Fapp%2Fnotes%3Fpage%3D2"
    );
    for mode in [Some("cors"), Some("same-origin"), Some("no-cors"), None] {
        let mut request = Request::get("/app/notes");
        if let Some(mode) = mode {
            request = request.header("sec-fetch-mode", mode);
        }
        let response = send_from(&app, request, (None, None)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{mode:?}");
    }
}

/// A layer inside a nested router redirects a step-up back to the full path, prefix
/// included, and recognizes the retry on that path; a `fetch` asked to step up gets
/// the 401 instead of a redirect.
#[tokio::test]
async fn step_ups_in_nested_routers_keep_their_prefix() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let issuer = endpoint.issuer(&clock());
    let key = CookieKey::generate().expect("cookie key");
    let auth = LoginRoutes::new(client(&issuer), key).expect("a confidential client");
    let settings = Router::new()
        .route(
            "/settings",
            get(|user: SignedIn| async move { user.step_up(StepUpRequirement::default()) }),
        )
        .layer(auth.layer());
    let app = Router::new()
        .nest("/app", settings)
        .nest("/auth", auth.router());
    let session = sign_in(&app, USER).await;
    let response = get_with(&app, "/app/settings", &[(header::COOKIE, &session)]).await;
    assert_eq!(
        response.headers()[header::LOCATION],
        "/auth/login?return_to=%2Fapp%2Fsettings&step_up=true"
    );
    let fetch = Request::get("/app/settings")
        .header("sec-fetch-mode", "cors")
        .header(header::COOKIE, &session);
    let response = send_from(&app, fetch, (None, None)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let marker = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(<sha2::Sha256 as sha2::Digest>::digest("/app/settings"));
    let cookies = format!("{session}; __Host-piquel-{CLIENT}-step-up={marker}");
    let response = get_with(&app, "/app/settings", &[(header::COOKIE, &cookies)]).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the retry is spent"
    );
}

/// Logins started together in tabs whose `state`s land in different slots both
/// complete, each reading and dropping only its own cookie. A callback naming
/// another `state` finds no login and leaves both alone, and however many logins
/// start at once, a browser holds at most three cookies, one per slot.
#[tokio::test]
async fn logins_in_several_tabs_complete() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let app = login_app(&endpoint.issuer(&clock()));
    // Start logins until every slot is used: random `state`s land in all three
    // within 200 but for a chance of about 1 in 10^35.
    let (mut started, mut slots) = (Vec::new(), std::collections::BTreeSet::new());
    while slots.len() < 3 && started.len() < 200 {
        let login = Started::at(&app, "%2Fnotes", &[]).await;
        slots.insert(login.name.clone());
        started.push(login);
    }
    assert_eq!(slots.len(), 3, "every login lands in one of three slots");
    let first = started.remove(0);
    let second = started
        .into_iter()
        .find(|login| login.name != first.name)
        .expect("a login in another slot");
    let both = [first.cookie.clone(), second.cookie.clone()];

    let forged = Started {
        name: String::new(),
        cookie: String::new(),
        state: "made-up".into(),
        nonce: second.nonce.clone(),
    };
    let response = forged.complete(&app, USER, &both).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookies(&response).is_empty(), "no login is touched");
    for login in [&second, &first] {
        let response = login.complete(&app, USER, &both).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/notes");
        assert_eq!(
            set_cookie(&response, &login.name),
            Some(format!("{}=", login.name))
        );
        assert!(
            set_cookie(&response, SESSION_COOKIE).is_some_and(|pair| !pair.ends_with('=')),
            "a session starts"
        );
        let cookies = set_cookies(&response);
        assert!(
            !cookies
                .iter()
                .any(|set| set.starts_with(PENDING_COOKIE) && !set.starts_with(&login.name)),
            "the other tab's login is kept: {cookies:?}"
        );
    }
}

/// Every pending login cookie fits its slot's 1000 bytes: a `return_to` too long for
/// it returns home instead, and to the root when the home path is too long as well.
#[tokio::test]
async fn pending_cookies_fit_their_slots() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let issuer = endpoint.issuer(&clock());
    // Quotes double in JSON, so 2048 of them would seal to some 6 KB.
    let quotes = format!("%2F{}", "%22".repeat(2047));
    let home = format!("/{}", "\"".repeat(2047))
        .parse()
        .expect("home path");
    for (app, destination) in [
        (login_app(&issuer), "/"),
        (
            login_app_with(&issuer, |routes| {
                routes.after_login("/notes".parse().expect("path"))
            }),
            "/notes",
        ),
        (
            login_app_with(&issuer, |routes| routes.after_login(home)),
            "/",
        ),
    ] {
        let login = Started::at(&app, &quotes, &[]).await;
        assert!(login.cookie.len() <= 1000, "{}", login.cookie.len());
        let response = login
            .complete(&app, USER, std::slice::from_ref(&login.cookie))
            .await;
        assert_eq!(response.headers()[header::LOCATION], destination);
    }
}

/// `Sec-Fetch-Site` and `Origin` headers, and whether they show the app's own pages:
/// `Sec-Fetch-Site` decides when sent, and `Origin` only without it. A form on a
/// `no-referrer` page sends `Origin: null` with `Sec-Fetch-Site: same-origin`.
const ORIGINS: [(Option<&str>, Option<&str>, bool); 8] = [
    (Some("same-origin"), Some("null"), true),
    (Some("same-origin"), None, true),
    (None, Some("https://notes.example.com"), true),
    (Some("same-site"), Some("https://notes.example.com"), false),
    (Some("cross-site"), Some("https://notes.example.com"), false),
    (None, Some("null"), false),
    (None, None, false),
    (None, Some("https://evil.notes.example.com"), false),
];

/// Sends `request` with a `Sec-Fetch-Site` and `Origin` from [`ORIGINS`].
async fn send_from(
    app: &Router,
    mut request: ::axum::http::request::Builder,
    (fetch_site, origin): (Option<&str>, Option<&str>),
) -> Response {
    if let Some(fetch_site) = fetch_site {
        request = request.header("sec-fetch-site", fetch_site);
    }
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

/// Logout is accepted only from the app's own pages.
#[tokio::test]
async fn logout_refuses_other_origins() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let app = login_app(&endpoint.issuer(&clock()));
    let session = sign_in(&app, USER).await;
    for (fetch_site, origin, own) in ORIGINS {
        let request = Request::post("/auth/logout").header(header::COOKIE, &session);
        let response = send_from(&app, request, (fetch_site, origin)).await;
        let case = format!("{fetch_site:?} {origin:?}");
        let expected = if own {
            StatusCode::SEE_OTHER
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected, "{case}");
        let cleared = set_cookie(&response, SESSION_COOKIE);
        assert_eq!(cleared.is_some(), own, "{case}");
    }
}

/// `SignedIn` and `MaybeSignedIn` take an unsafe request only from the app's own
/// pages, so no other site, not even a sibling the cookie reaches, acts as the user;
/// without a cookie too, it is refused rather than asked to sign in. Safe methods and
/// [`CrossOrigin`] skip the check.
#[tokio::test]
async fn signed_in_refuses_unsafe_requests_from_other_origins() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let app = login_app(&endpoint.issuer(&clock()));
    let cookie = sign_in(&app, USER).await;
    let signed_in =
        |request: ::axum::http::request::Builder| request.header(header::COOKIE, cookie.as_str());
    for (fetch_site, origin, own) in ORIGINS {
        let from = (fetch_site, origin);
        let case = format!("{fetch_site:?} {origin:?}");
        let (allowed, refused) = (StatusCode::OK, StatusCode::FORBIDDEN);
        let expected = if own { allowed } else { refused };
        for request in [
            signed_in(Request::post("/notes")),
            signed_in(Request::delete("/notes")),
            signed_in(Request::post("/maybe")),
            Request::post("/maybe"),
        ] {
            let response = send_from(&app, request, from).await;
            assert_eq!(response.status(), expected, "{case}");
        }
        let anonymous = send_from(&app, Request::post("/notes"), from).await;
        let expected = if own {
            StatusCode::UNAUTHORIZED
        } else {
            refused
        };
        assert_eq!(anonymous.status(), expected, "anonymous {case}");
        let page = send_from(&app, signed_in(Request::get("/")), from).await;
        assert_eq!(page.status(), allowed, "GET {case}");
        for path in ["/widget", "/maybe-widget"] {
            let response = send_from(&app, signed_in(Request::post(path)), from).await;
            assert_eq!(response.status(), allowed, "{path} {case}");
        }
    }
}

/// Another account than the session's.
const OTHER: &str = "01936f3e-8c00-7000-8000-000000000009";

/// A step-up must sign in the user it started from, and the one whose session it
/// replaces: otherwise it fails with 400 and keeps that session, its refresh token
/// unrevoked, while the grant it was refused revokes. An ordinary sign-in may switch
/// accounts.
#[tokio::test]
async fn step_ups_stay_on_the_signed_in_account() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let app = login_app(&endpoint.issuer(&clock()));
    let session = sign_in(&app, USER).await;
    let step_up = "%2F&step_up=true";
    let refused = |response: &Response| {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            set_cookie(response, SESSION_COOKIE),
            None,
            "the session is kept"
        );
    };

    // Started from the session, then completed as another account.
    let login = Started::at(&app, step_up, std::slice::from_ref(&session)).await;
    let both = [login.cookie.clone(), session.clone()];
    refused(&login.complete(&app, OTHER, &both).await);
    // Started from the session, which another tab then signed out of: the pin alone
    // stops another account.
    let login = Started::at(&app, step_up, std::slice::from_ref(&session)).await;
    refused(
        &login
            .complete(&app, OTHER, std::slice::from_ref(&login.cookie))
            .await,
    );
    // Started without a session, then completed beside another account's.
    let login = Started::at(&app, step_up, &[]).await;
    let both = [login.cookie.clone(), session.clone()];
    refused(&login.complete(&app, OTHER, &both).await);
    // The session's grant is `refresh-0`; each refused sign-in's, revoked, the next.
    assert_eq!(
        *endpoint.revoked.lock().expect("revoked"),
        ["refresh-1", "refresh-2", "refresh-3"]
    );

    let login = Started::at(&app, step_up, std::slice::from_ref(&session)).await;
    let both = [login.cookie.clone(), session.clone()];
    let response = login.complete(&app, USER, &both).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        endpoint
            .revoked
            .lock()
            .expect("revoked")
            .last()
            .map(String::as_str),
        Some("refresh-0"),
        "the replaced session's grant"
    );

    let login = Started::at(&app, "%2F", std::slice::from_ref(&session)).await;
    let both = [login.cookie.clone(), session];
    let response = login.complete(&app, OTHER, &both).await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "an ordinary sign-in"
    );
}

/// A login with `id_token_hint` sends it to auth, and completes only for the user it
/// names; another user's grant is revoked as it is refused.
#[tokio::test]
async fn hinted_logins_complete_only_for_the_hinted_user() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let client = client(&endpoint.issuer(&clock()));
    let hint: crate::IdToken =
        serde_json::from_value(json!({ "claims": id_claims(USER), "raw": "id-0" }))
            .expect("ID token");
    let request = crate::AuthorizeRequest {
        id_token_hint: Some(hint),
        ..crate::AuthorizeRequest::default()
    };
    for (sub, completes) in [(OTHER, false), (USER, true)] {
        let (url, pending) = client.authorize(&request).await.expect("authorize");
        let parameter = |name: &str| {
            url.query_pairs()
                .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
                .expect("parameter")
        };
        assert_eq!(parameter("id_token_hint"), "id-0");
        let callback = crate::CallbackParams {
            code: Some(code(sub, &parameter("nonce"))),
            state: Some(parameter("state")),
            iss: Some("https://auth.example.com".into()),
            ..crate::CallbackParams::default()
        };
        let completed = client.complete(pending, &callback).await;
        assert_eq!(completed.is_ok(), completes, "{sub}");
        let revoked = endpoint.revoked.lock().expect("revoked").clone();
        assert_eq!(revoked, ["refresh-0"], "only the refused grant, {sub}");
        if let Err(error) = completed {
            assert_eq!(
                error.code(),
                crate::SdkError::new(
                    crate::protocol::sdk::ErrorCategory::InvalidToken,
                    crate::protocol::sdk::ErrorReason::SubjectMismatch
                )
            );
        }
    }
}
