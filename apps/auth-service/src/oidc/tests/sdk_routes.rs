//! The Rust SDK's login routes, pushing and step-up against the real provider.

use super::*;
use piquel_common::protocol::step_up::StepUpRequirement;

/// A clock the SDK scenarios move by hand, to reach access token expiry.
#[derive(Clone)]
struct ManualClock(Arc<std::sync::Mutex<chrono::DateTime<Utc>>>);

impl ManualClock {
    /// Moves the clock forward.
    fn advance(&self, seconds: i64) {
        *self.0.lock().expect("clock") += chrono::TimeDelta::seconds(seconds);
    }
}

impl piquel_auth::Clock for ManualClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        *self.0.lock().expect("clock")
    }
}

/// An app using the SDK's login routes against the provider, served in-process.
struct LoginApp {
    /// The provider scenario.
    flow: Flow,
    /// The app's routes; `/` shows the session's access token.
    app: Router,
    /// The SDK's clock.
    clock: ManualClock,
}

impl LoginApp {
    /// Serves the provider over TLS and builds the app.
    async fn start() -> Self {
        use piquel_auth::{
            ClientConfig, Credentials, Resource,
            axum::{BearerLayer, CookieKey, LoginRoutes, RequireAuthentication, SignedIn},
            protocol::challenge::BearerChallenge,
        };
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind provider");
        let port = tcp.local_addr().expect("provider address").port();
        let origin = format!("https://localhost:{port}");
        let flow = Flow::at(&origin, true, false).await;
        let certificate = TlsListener::serve(tcp, flow.app.clone().routes());
        let http = reqwest::Client::builder()
            .add_root_certificate(certificate)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("HTTP client");
        let clock = ManualClock(Arc::new(std::sync::Mutex::new(Utc::now())));
        let issuer = piquel_auth::Issuer::builder()
            .http_client(http)
            .clock(clock.clone())
            .discover(&origin)
            .await
            .expect("discover the provider");
        let client = issuer.client(ClientConfig {
            client_id: flow.client.id.clone(),
            credentials: Credentials::Secret(flow.secret.clone().expect("confidential").into()),
            redirect_uri: flow.client.redirect_uris[0]
                .as_str()
                .parse()
                .expect("callback"),
        });
        // An API the app calls with the user's token: `/settings` needs a recent
        // passkey, and `/stubborn` asks for a step-up, naming nothing, whatever the
        // token holds.
        let api = Router::new()
            .route(
                "/settings",
                axum::routing::get(|_: RequireAuthentication<RecentPasskey>| async { "settings" }),
            )
            .route(
                "/stubborn",
                axum::routing::get(|| async {
                    let challenge = BearerChallenge::step_up(StepUpRequirement::default());
                    (
                        StatusCode::UNAUTHORIZED,
                        [(header::WWW_AUTHENTICATE, challenge.to_string())],
                    )
                }),
            )
            .layer(BearerLayer::new(issuer.resource(
                Resource::new(flow.client.id.as_str()).expect("resource"),
            )));
        let call_api = move |path: &'static str| {
            let api = api.clone();
            move |user: SignedIn| async move {
                let request = Request::get(path)
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", user.login().access_token().expose()),
                    )
                    .body(Body::empty())
                    .expect("API request");
                let answer = api.oneshot(request).await.expect("API response");
                let challenge = answer
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<BearerChallenge>().ok());
                match challenge {
                    Some(challenge) => user.step_up(challenge.step_up).into_response(),
                    None => answer,
                }
            }
        };
        let key = CookieKey::generate().expect("cookie key");
        let auth = LoginRoutes::new(client, key)
            .expect("a confidential client")
            .scopes("profile".parse().expect("scopes"))
            .after_logout(
                flow.client.post_logout_uris[0]
                    .as_str()
                    .parse()
                    .expect("logout URI"),
            );
        let app = Router::new()
            .route(
                "/notes",
                axum::routing::get(|user: SignedIn| async move {
                    user.login().access_token().expose().to_owned()
                }),
            )
            .route("/settings", axum::routing::get(call_api("/settings")))
            .route("/stubborn", axum::routing::get(call_api("/stubborn")))
            .nest("/auth", auth.router())
            .layer(auth.layer());
        Self { flow, app, clock }
    }

    /// The name of the login routes' cookie ending in `suffix`, which names the
    /// client.
    fn named(&self, suffix: &str) -> String {
        format!("__Host-piquel-{}-{suffix}", self.flow.client.id)
    }

    /// Sends a request to the app with an optional cookie. Posts carry the app's
    /// `Origin`, as a browser on its pages sends.
    async fn send(&self, method: Method, uri: &str, cookie: Option<&str>) -> Response {
        let mut request = Request::builder().method(method.clone()).uri(uri);
        if method == Method::POST {
            let callback =
                Url::parse(self.flow.client.redirect_uris[0].as_str()).expect("callback");
            request = request.header(header::ORIGIN, callback.origin().ascii_serialization());
        }
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.app
            .clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response")
    }

    /// The `Set-Cookie` values of a response.
    fn cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("cookie").to_owned())
            .collect()
    }

    /// The `name=value` pair of the cookie `name` that `response` sets.
    fn cookie(response: &Response, name: &str) -> String {
        Self::cookies(response)
            .into_iter()
            .find(|cookie| cookie.starts_with(&format!("{name}=")))
            .and_then(|cookie| cookie.split(';').next().map(str::to_owned))
            .expect("cookie set")
    }

    /// The relative `Location` of an app redirect.
    fn location(response: &Response) -> String {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response.headers()[header::LOCATION]
            .to_str()
            .expect("location")
            .to_owned()
    }

    /// Starts login at `login` (the app's login path and query): the pending login's
    /// cookie, and the provider's authorization URL.
    async fn start_login(&self, login: &str, session: Option<&str>) -> (String, Url) {
        let start = self.send(Method::GET, login, session).await;
        for cookie in Self::cookies(&start) {
            assert!(
                cookie.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"),
                "{cookie}"
            );
        }
        // Pushed requests keep `state` out of the URL: the cookie is named for it.
        let pending = self.named("login-");
        let cookie = Self::cookies(&start)
            .into_iter()
            .find(|cookie| cookie.starts_with(&pending))
            .and_then(|cookie| cookie.split(';').next().map(str::to_owned))
            .expect("pending login cookie");
        (
            cookie,
            Url::parse(&Self::location(&start)).expect("authorization URL"),
        )
    }

    /// The provider's answer to the browser following `authorize`.
    async fn authorize(&self, authorize: &Url) -> Response {
        self.flow
            .request(
                Method::GET,
                &format!("{}?{}", authorize.path(), authorize.query().expect("query")),
                &[],
                None,
            )
            .await
    }

    /// Consents at the provider and returns the app callback's response.
    async fn finish_login(
        &self,
        browser: Response,
        pending: String,
        session: Option<&str>,
    ) -> Response {
        let callback = self.flow.consent(browser).await;
        let cookies = match session {
            Some(session) => format!("{pending}; {session}"),
            None => pending,
        };
        self.send(
            Method::GET,
            &format!("/auth/callback?{}", callback.query().expect("query")),
            Some(&cookies),
        )
        .await
    }

    /// Starts login at `login`, signs in at the provider, and returns the callback's
    /// response.
    async fn sign_in(&self, login: &str, session: Option<&str>) -> Response {
        let (pending, authorize) = self.start_login(login, session).await;
        let browser = self.authorize(&authorize).await;
        self.finish_login(browser, pending, session).await
    }
}

/// The SDK's login routes sign a user in through the provider, keep tokens in the
/// session cookie, refresh them there, refuse open redirects, and log out through
/// the provider. Logout revokes the refresh token, so a copy of the cookie ends at
/// its next refresh.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sdk_login_routes_run_against_the_provider() {
    let app = LoginApp::start().await;
    let page = app.send(Method::GET, "/notes?page=2", None).await;
    assert_eq!(
        LoginApp::location(&page),
        "/auth/login?return_to=%2Fnotes%3Fpage%3D2"
    );

    let callback = app.sign_in(&LoginApp::location(&page), None).await;
    assert_eq!(LoginApp::location(&callback), "/notes?page=2");
    let cookies = LoginApp::cookies(&callback);
    let session = app.named("session");
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with(&format!("{session}="))
                && cookie.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=43200"))
    );
    let pending = app.named("login-");
    assert!(cookies.iter().any(|cookie| cookie.starts_with(&pending)
        && cookie.ends_with("=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")));
    let first = LoginApp::cookie(&callback, &app.named("session"));
    let shown = app.send(Method::GET, "/notes", Some(&first)).await;
    assert_eq!(shown.status(), StatusCode::OK);
    let access = Flow::text(shown).await;

    // A second sign-in replaces the browser's session.
    let callback = app.sign_in("/auth/login", Some(&first)).await;
    assert_eq!(LoginApp::location(&callback), "/");
    let second = LoginApp::cookie(&callback, &app.named("session"));
    assert_ne!(first, second);

    // Near expiry, the access token is refreshed, and the response carries it.
    app.clock.advance(290);
    let refreshed = app.send(Method::GET, "/notes", Some(&second)).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let copy = LoginApp::cookie(&refreshed, &app.named("session"));
    assert_ne!(Flow::text(refreshed).await, access);

    // Open redirects are refused: login falls back to the home page.
    let callback = app
        .sign_in("/auth/login?return_to=%2F%2Fevil.example", None)
        .await;
    assert_eq!(LoginApp::location(&callback), "/");

    let logout = app.send(Method::POST, "/auth/logout", Some(&second)).await;
    let destination = Url::parse(&LoginApp::location(&logout)).expect("logout URL");
    assert_eq!(destination.path(), "/oidc/logout");
    assert_eq!(
        parameter(&destination, "post_logout_redirect_uri"),
        app.flow.client.post_logout_uris[0].as_str()
    );
    assert!(
        LoginApp::cookies(&logout)
            .iter()
            .any(|cookie| cookie.starts_with(&format!("{}=;", app.named("session"))))
    );
    // A copy of the cookie works until its access token expires, then its refresh is
    // refused: the session ends, and its cookie is cleared.
    let kept = app.send(Method::GET, "/notes", Some(&copy)).await;
    assert_eq!(kept.status(), StatusCode::OK);
    app.clock.advance(300);
    let after = app.send(Method::GET, "/notes", Some(&copy)).await;
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
    assert!(
        LoginApp::cookies(&after)
            .iter()
            .any(|cookie| cookie.starts_with(&format!("{}=;", app.named("session"))))
    );
}

/// A client required to push its authorization requests signs in through the SDK's
/// login routes, which push them, so the browser carries only the `request_uri`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sdk_login_routes_push_for_clients_that_must() {
    let mut app = LoginApp::start().await;
    app.flow.client.require_pushed_authorization_requests = true;
    crate::tests::replace(&app.flow.app.database, &app.flow.client)
        .await
        .expect("require pushed requests");
    let (pending, authorize) = app.start_login("/auth/login", None).await;
    let names: Vec<_> = authorize.query_pairs().map(|(name, _)| name).collect();
    assert_eq!(names, ["client_id", "request_uri"]);
    let browser = app.authorize(&authorize).await;
    let callback = app.finish_login(browser, pending, None).await;
    assert_eq!(LoginApp::location(&callback), "/");
}

/// A passkey confirmation within five minutes.
struct RecentPasskey;

impl piquel_auth::AuthenticationPolicy for RecentPasskey {
    const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(300);
}

/// An app whose API needs a recent passkey sends a socially signed-in user through
/// the provider with the API's `acr_values` and `max_age`, then back to the page,
/// which now works. An API that still refuses after one step-up gets an error, not
/// another sign-in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sdk_step_up_runs_against_the_provider() {
    let mut app = LoginApp::start().await;
    app.flow
        .sign_in_again(AuthenticationMethod::Federation)
        .await;
    let callback = app.sign_in("/auth/login", None).await;
    let first = LoginApp::cookie(&callback, &app.named("session"));

    let page = app.send(Method::GET, "/settings", Some(&first)).await;
    let login = LoginApp::location(&page);
    assert_eq!(
        login,
        "/auth/login?return_to=%2Fsettings&acr_values=phr&max_age=300&step_up=true"
    );
    // The pushed request carries `acr_values` and `max_age`: the social session is
    // too weak for them, so the provider asks for a passkey.
    let (pending, authorize) = app.start_login(&login, Some(&first)).await;
    let prompt = app.authorize(&authorize).await;
    assert_eq!(location(&prompt).path(), routes::page::LOGIN);

    let access = app.send(Method::GET, "/notes", Some(&first)).await;
    let access = Flow::text(access).await;
    let payload = access.split('.').nth(1).expect("JWT payload");
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url payload"),
    )
    .expect("claims");
    let session = claims["sid"]
        .as_str()
        .expect("sid")
        .parse()
        .expect("session ID");
    app.flow
        .app
        .database
        .sessions()
        .confirm_passkey(session, PasskeyId::new(), Utc::now())
        .await
        .expect("passkey confirmation");
    // The pushed request was claimed, so the browser resumes its transaction.
    let transaction = parameter(&location(&prompt), "transaction");
    let browser = app
        .flow
        .request(
            Method::GET,
            &format!(
                "{}?transaction={transaction}",
                routes::oidc::AUTHORIZE_RESUME
            ),
            &[],
            None,
        )
        .await;
    let callback = app.finish_login(browser, pending, Some(&first)).await;
    assert_eq!(LoginApp::location(&callback), "/settings");
    let second = LoginApp::cookie(&callback, &app.named("session"));
    let retry = LoginApp::cookie(&callback, &app.named("step-up"));

    let page = app
        .send(
            Method::GET,
            "/settings",
            Some(&format!("{second}; {retry}")),
        )
        .await;
    assert!(
        LoginApp::cookies(&page)
            .iter()
            .any(|cookie| cookie.starts_with(&format!("{}=;", app.named("step-up")))),
        "the retry marker is used up"
    );
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(Flow::text(page).await, "settings");

    // An API that refuses whatever the token holds gets one step-up sign-in, then an
    // error on the retry instead of another redirect, even when its challenge names
    // no requirement.
    let page = app.send(Method::GET, "/stubborn", Some(&second)).await;
    let login = LoginApp::location(&page);
    assert_eq!(login, "/auth/login?return_to=%2Fstubborn&step_up=true");
    let callback = app.sign_in(&login, Some(&second)).await;
    assert_eq!(LoginApp::location(&callback), "/stubborn");
    let third = LoginApp::cookie(&callback, &app.named("session"));
    let retry = LoginApp::cookie(&callback, &app.named("step-up"));
    let cookies = format!("{third}; {retry}");
    // Only the returning `GET` is the retry.
    let other = app.send(Method::POST, "/stubborn", Some(&cookies)).await;
    assert_eq!(LoginApp::cookies(&other), Vec::<String>::new());
    let refused = app.send(Method::GET, "/stubborn", Some(&cookies)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    // An ordinary sign-in drops a marker its return never used.
    let page = app.send(Method::GET, "/stubborn", Some(&third)).await;
    let callback = app.sign_in(&LoginApp::location(&page), Some(&third)).await;
    let fourth = LoginApp::cookie(&callback, &app.named("session"));
    let unused = LoginApp::cookie(&callback, &app.named("step-up"));
    let callback = app.sign_in("/auth/login", Some(&fourth)).await;
    assert!(
        LoginApp::cookies(&callback)
            .iter()
            .any(|cookie| cookie.starts_with(&format!("{}=;", app.named("step-up")))),
        "the unused marker {unused} is dropped"
    );
}
