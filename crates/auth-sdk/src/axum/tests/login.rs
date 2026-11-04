//! Login's redirects, `return_to`, and the origin checks on logout and the session
//! extractors.

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

/// Without a session, a page is redirected through login and back to its full path,
/// prefix included when it sits in a nested router.
#[tokio::test]
async fn signed_in_redirects_back_to_the_full_path() {
    let backend = MemoryBackend::default();
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    let (app, _) = login_app(&issuer, &backend);
    let response = get_with(&app, "/app/notes?page=2", &[]).await;
    assert_eq!(
        response.headers()[header::LOCATION],
        "/auth/login?return_to=%2Fapp%2Fnotes%3Fpage%3D2"
    );
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
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    for (fetch_site, origin, own) in ORIGINS {
        let backend = MemoryBackend::default();
        let (app, _) = login_app(&issuer, &backend);
        let login = stored_login(USER, SessionId::new(), 300);
        let (key, cookie) = session(&backend, &login).await;
        let request = Request::post("/auth/logout").header(header::COOKIE, cookie);
        let response = send_from(&app, request, (fetch_site, origin)).await;
        let case = format!("{fetch_site:?} {origin:?}");
        let expected = if own {
            StatusCode::SEE_OTHER
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected, "{case}");
        assert_eq!(load(&backend, &key).await.is_none(), own, "{case}");
    }
}

/// `SignedIn` and `MaybeSignedIn` take an unsafe request only from the app's own
/// pages, so no other site, not even a sibling the cookie reaches, acts as the user;
/// without a cookie too, it is refused rather than asked to sign in. Safe methods and
/// [`CrossOrigin`] skip the check.
#[tokio::test]
async fn signed_in_refuses_unsafe_requests_from_other_origins() {
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    let backend = MemoryBackend::default();
    let (app, _) = login_app(&issuer, &backend);
    let (_, cookie) = session(&backend, &stored_login(USER, SessionId::new(), 300)).await;
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

/// The cookie prefix of the test client's pending logins.
const PENDING_COOKIE: &str = "__Host-piquel-notes-web-login-";

/// A login started at `/auth/login`: its cookie's `name=value` pair, and the `state`
/// and `nonce` its redirect to auth carries.
struct Started {
    /// The pending login's cookie.
    cookie: String,
    /// The login's `state`.
    state: String,
    /// The login's `nonce`.
    nonce: String,
}

impl Started {
    /// Starts a login returning to `return_to`, in a browser holding `cookies`; returns
    /// it with the cookies the response dropped.
    async fn at(app: &Router, return_to: &str, cookies: &[String]) -> (Self, Vec<String>) {
        let path = format!("/auth/login?return_to={return_to}");
        let headers = [(header::COOKIE, cookies.join("; "))];
        let headers: Vec<_> = headers
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, value)| (name.clone(), value.as_str()))
            .collect();
        let response = get_with(app, &path, &headers).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location: Url = response.headers()[header::LOCATION]
            .to_str()
            .expect("location")
            .parse()
            .expect("authorization URL");
        let parameter = |name: &str| {
            location
                .query_pairs()
                .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
                .expect("parameter")
        };
        let (state, nonce) = (parameter("state"), parameter("nonce"));
        let (mut cookie, mut dropped) = (None, Vec::new());
        for set in set_cookies(&response) {
            let pair = set.split(';').next().expect("pair").to_owned();
            if pair.ends_with('=') {
                dropped.push(pair.trim_end_matches('=').to_owned());
            } else {
                assert!(set.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"));
                assert!(
                    pair.starts_with(&format!("{PENDING_COOKIE}{state}=")),
                    "{pair}"
                );
                cookie = Some(pair);
            }
        }
        let cookie = cookie.expect("pending login cookie");
        (
            Self {
                cookie,
                state,
                nonce,
            },
            dropped,
        )
    }

    /// The callback completing this login for `sub`, in a browser holding `cookies`.
    async fn complete(&self, app: &Router, sub: &str, cookies: &[String]) -> Response {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code(sub, &self.nonce))
            .append_pair("state", &self.state)
            .append_pair("iss", "https://auth.example.com")
            .finish();
        let cookies = cookies.join("; ");
        get_with(
            app,
            &format!("/auth/callback?{query}"),
            &[(header::COOKIE, &cookies)],
        )
        .await
    }

    /// The pending login's cookie name.
    fn name(&self) -> String {
        format!("{PENDING_COOKIE}{}", self.state)
    }
}

/// The `Set-Cookie` values of `response`.
fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("cookie").to_owned())
        .collect()
}

/// Logins started together in two tabs both complete: each keeps its own cookie,
/// named for its `state`, and no login writes to the backend. A callback naming
/// another `state` finds no login and leaves both alone, and a browser keeps at most
/// three logins, dropping the oldest.
#[tokio::test]
async fn logins_in_several_tabs_complete() {
    let backend = Spy::default();
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let (app, _) = login_app(&issuer_with_token_endpoint(endpoint.url.clone()), &backend);
    let (first, _) = Started::at(&app, "%2Fnotes", &[]).await;
    let (second, _) = Started::at(&app, "%2Fsettings", std::slice::from_ref(&first.cookie)).await;
    assert!(
        backend.dump().await.is_empty(),
        "anonymous logins write nothing"
    );
    let both = [first.cookie.clone(), second.cookie.clone()];

    let forged = Started {
        cookie: String::new(),
        state: "made-up".into(),
        nonce: second.nonce.clone(),
    };
    let response = forged.complete(&app, USER, &both).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(set_cookies(&response).is_empty(), "no login is touched");
    for (login, page) in [(&second, "/settings"), (&first, "/notes")] {
        let response = login.complete(&app, USER, &both).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], page);
        let cookies = set_cookies(&response);
        let cleared: Vec<_> = cookies.iter().filter(|set| set.contains("=;")).collect();
        assert!(
            cleared
                .iter()
                .any(|set| set.starts_with(&format!("{}=;", login.name()))),
            "{cookies:?}"
        );
        assert!(
            cookies
                .iter()
                .any(|set| set.starts_with(&format!("{SESSION_COOKIE}=")) && !set.contains("=;"))
        );
        assert!(
            !cookies
                .iter()
                .any(|set| set.starts_with(PENDING_COOKIE) && !set.starts_with(&login.name())),
            "the other tab's login is kept"
        );
    }

    let mut held = Vec::new();
    let mut started = Vec::new();
    for _ in 0..4 {
        let (login, dropped) = Started::at(&app, "%2F", &held).await;
        held.retain(|cookie: &String| {
            !dropped
                .iter()
                .any(|name| cookie.starts_with(&format!("{name}=")))
        });
        held.push(login.cookie.clone());
        started.push((login, dropped));
    }
    let (_, dropped) = &started[3];
    assert_eq!(
        dropped,
        &[started[0].0.name()],
        "the oldest login is dropped"
    );
    assert_eq!(held.len(), 3);
}

/// A cookie whose name only starts like this app's pending logins, such as the
/// session of an app whose client ID is `notes-web-login-admin`, is never read or
/// dropped: neither by a new login nor by a callback whose `state` names it.
#[tokio::test]
async fn pending_logins_leave_other_apps_cookies_alone() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let (app, _) = login_app(
        &issuer_with_token_endpoint(endpoint.url.clone()),
        &MemoryBackend::default(),
    );
    let other = format!("{PENDING_COOKIE}admin-session=c2Vzc2lvbg");
    let (_, dropped) = Started::at(&app, "%2F", std::slice::from_ref(&other)).await;
    assert!(dropped.is_empty(), "{dropped:?}");
    let forged = Started {
        cookie: String::new(),
        state: "admin-session".into(),
        nonce: "n".into(),
    };
    let response = forged.complete(&app, USER, &[other]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(set_cookies(&response), Vec::<String>::new());
}

/// A `return_to` too long for a cookie returns home instead, so the login still
/// completes, and logins whose cookies together outgrow a `Cookie` header's share
/// drop the oldest first.
#[tokio::test]
async fn pending_cookies_fit_in_a_header() {
    let endpoint = TokenEndpoint::start(Duration::ZERO).await;
    let (app, _) = login_app(
        &issuer_with_token_endpoint(endpoint.url.clone()),
        &MemoryBackend::default(),
    );
    // Quotes double in JSON, so 2048 of them would seal to some 6 KB.
    let quotes = format!("%2F{}", "%22".repeat(2047));
    let (login, _) = Started::at(&app, &quotes, &[]).await;
    assert!(login.cookie.len() <= 4000, "{}", login.cookie.len());
    let response = login
        .complete(&app, USER, std::slice::from_ref(&login.cookie))
        .await;
    assert_eq!(response.headers()[header::LOCATION], "/");

    // Each of these fits on its own, but no three fit together.
    let long = format!("%2F{}", "a".repeat(1500));
    let mut held: Vec<String> = Vec::new();
    let mut names = Vec::new();
    for _ in 0..3 {
        let (login, dropped) = Started::at(&app, &long, &held).await;
        held.retain(|cookie| {
            !dropped
                .iter()
                .any(|name| cookie.starts_with(&format!("{name}=")))
        });
        held.push(login.cookie.clone());
        names.push((login.name(), dropped));
    }
    assert_eq!(names[2].1, [names[0].0.clone()], "the oldest is dropped");
    assert!(held.iter().map(String::len).sum::<usize>() <= 6000);
}
