//! Fixtures the axum integration's tests share: the vectors' issuer, a token
//! endpoint, an app behind the login layer, and signing in to it.

/// Back-channel logout.
mod backchannel;
/// Bearer rejections.
mod bearer;
/// Login routes, pending logins and origin checks.
mod login;
/// Session cookies, refresh and logout.
mod sessions;

use super::*;
use crate::{
    AuthenticationPolicy, ClientConfig, ClientId, Credentials, Issuer, KeyCache, KeySet, Resource,
    StepUpRequirement,
    http::Http,
    tests::{Case, ManualClock, issuer, metadata, serve, vector_token},
};
use ::axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use chrono::Utc;
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;
use url::Url;

crate::scopes! {
    /// Scopes of the test API.
    mod notes {
        Read = "notes:read",
        Write = "notes:write",
    }
}

/// A passkey confirmation within five minutes.
struct RecentPasskey;

impl AuthenticationPolicy for RecentPasskey {
    const REQUIREMENT: StepUpRequirement = StepUpRequirement::passkey_within(300);
}

/// Resource identifier of the token vectors.
const RESOURCE: &str = "https://notes.example.com";
/// Client of the vectors' ID tokens.
const CLIENT: &str = "notes-web";
/// The test client's session cookie.
const SESSION_COOKIE: &str = "__Host-piquel-notes-web-session";
/// The fixture user's account ID.
const USER: &str = "01936f3e-8c00-7000-8000-000000000001";

/// A token vector case by name.
fn token_case(name: &str) -> Case {
    Case::all("tokens")
        .into_iter()
        .find(|case| case.name.ends_with(&format!("/{name}.json")))
        .expect("token vector")
}

/// Sends a `GET` with optional `Authorization` and `Cookie` values, as a browser
/// navigating to a page (`Sec-Fetch-Mode: navigate`).
async fn get_with(app: &Router, path: &str, headers: &[(header::HeaderName, &str)]) -> Response {
    let mut request = Request::get(path).header("sec-fetch-mode", "navigate");
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
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

/// The `name=value` pair `response` sets for cookie `name`, if it sets one, with an
/// empty value when it deletes it.
fn set_cookie(response: &Response, name: &str) -> Option<String> {
    set_cookies(response).into_iter().find_map(|set| {
        let pair = set.split(';').next()?;
        pair.starts_with(&format!("{name}="))
            .then(|| pair.to_owned())
    })
}

/// The response body as text.
async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1024)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("UTF-8")
}

/// Auth's token and revocation endpoints on a local port, counting the refreshes they
/// answer and recording the tokens revoked.
struct TokenEndpoint {
    /// The token endpoint's URL.
    url: Url,
    /// The revocation endpoint's URL.
    revocation: Url,
    /// Refreshes answered or in progress.
    refreshes: Arc<AtomicUsize>,
    /// Every token revoked.
    revoked: Arc<Mutex<Vec<String>>>,
    /// Revocation requests that reached the endpoint, answered or not.
    revocations_received: Arc<AtomicUsize>,
    /// Whether revocations fail, as when auth is down.
    revocations_fail: Arc<AtomicBool>,
    /// Whether revocations hang for an hour before answering, as a stuck auth would.
    revocations_hang: Arc<AtomicBool>,
}

/// The form a token or revocation request posts.
type Form = std::collections::HashMap<String, String>;

impl TokenEndpoint {
    /// Serves endpoints whose `n`th refresh answers, after `delay`, `access-n` and no
    /// refresh token, as auth answers a confidential client.
    async fn start(delay: Duration) -> Self {
        Self::refreshing(move |call| async move {
            tokio::time::sleep(delay).await;
            ::axum::Json(Self::tokens(&format!("access-{call}"))).into_response()
        })
        .await
    }

    /// Serves endpoints refusing every refresh with `status` and `error`.
    async fn refusing(status: StatusCode, error: &'static str) -> Self {
        Self::refreshing(move |_| async move {
            (status, ::axum::Json(json!({ "error": error }))).into_response()
        })
        .await
    }

    /// Fresh tokens holding `access`, without an ID token or a refresh token.
    fn tokens(access: &str) -> serde_json::Value {
        json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "openid offline_access",
        })
    }

    /// Serves the endpoints. A code is redeemed with an ID token for the user and
    /// nonce it names ([`code`]), `access-0` and the refresh token `refresh-0`; the
    /// `n`th refresh is answered with `refresh(n)`.
    async fn refreshing<F, Fut>(refresh: F) -> Self
    where
        F: Fn(usize) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send,
    {
        let refreshes = Arc::new(AtomicUsize::new(0));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let revocations_received = Arc::new(AtomicUsize::new(0));
        let revocations_fail = Arc::new(AtomicBool::new(false));
        let revocations_hang = Arc::new(AtomicBool::new(false));
        let (counted, recorded, received, failing, hanging) = (
            refreshes.clone(),
            revoked.clone(),
            revocations_received.clone(),
            revocations_fail.clone(),
            revocations_hang.clone(),
        );
        let token = move |::axum::Form(form): ::axum::Form<Form>| {
            let (counted, refresh) = (counted.clone(), refresh.clone());
            async move {
                let Some(code) = form.get("code") else {
                    return refresh(counted.fetch_add(1, Ordering::SeqCst) + 1).await;
                };
                let (sub, nonce) = code.split_once('.').expect("a code from `code`");
                let mut tokens = Self::tokens("access-0");
                tokens["id_token"] = json!(id_token(sub, nonce));
                tokens["refresh_token"] = json!("refresh-0");
                ::axum::Json(tokens).into_response()
            }
        };
        let revoke = move |::axum::Form(form): ::axum::Form<Form>| async move {
            received.fetch_add(1, Ordering::SeqCst);
            if hanging.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            if failing.load(Ordering::SeqCst) {
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            recorded
                .lock()
                .expect("revocations")
                .push(form["token"].clone());
            StatusCode::OK
        };
        let router = Router::new()
            .route("/token", post(token))
            .route("/revoke", post(revoke));
        let address = serve(router).await;
        Self {
            url: format!("http://{address}/token").parse().expect("URL"),
            revocation: format!("http://{address}/revoke").parse().expect("URL"),
            refreshes,
            revoked,
            revocations_received,
            revocations_fail,
            revocations_hang,
        }
    }

    /// The vectors' issuer, using these endpoints, at `clock`.
    fn issuer(&self, clock: &ManualClock) -> Issuer {
        self.issuer_with(clock, Http::default_client().expect("HTTP client"))
    }

    /// The vectors' issuer, using these endpoints through `http`, at `clock`.
    fn issuer_with(&self, clock: &ManualClock, http: Http) -> Issuer {
        let mut metadata = metadata();
        metadata.token_endpoint = self.url.clone();
        metadata.revocation_endpoint = self.revocation.clone();
        // Logins redirect at once, with the request in the URL.
        metadata.pushed_authorization_request_endpoint = None;
        let jwks = serde_json::to_vec(token_case("access-valid").input("jwks")).expect("JWKS");
        Issuer::with_keys(
            metadata,
            KeyCache::fixed(KeySet::parse(&jwks).expect("keys")),
            http,
            Arc::new(clock.clone()),
        )
    }
}

/// A clock at the current time, which the vectors' ID tokens are signed at.
fn clock() -> ManualClock {
    ManualClock::at(Utc::now().timestamp())
}

/// The code [`TokenEndpoint::start`] redeems for `sub`'s sign-in with `nonce`.
fn code(sub: &str, nonce: &str) -> String {
    format!("{sub}.{nonce}")
}

/// Signs `claims` as auth signs tokens of `typ`, with the vectors' `key-2025`.
fn sign(claims: &serde_json::Value, typ: &str) -> String {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, crypto::aws_lc::DEFAULT_PROVIDER};
    let pem = include_str!("../../../../../tests/sdk-vectors/keys/key-2025.pem");
    let pkcs8 = STANDARD
        .decode(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .expect("PEM");
    // jsonwebtoken reads RSA keys in PKCS#1 form, which the PKCS#8 form of a
    // 2048-bit key wraps in a fixed 26-byte header.
    let key = EncodingKey::from_rsa_der(&pkcs8[26..]);
    let encode = |value: &serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let header = json!({ "alg": "RS256", "kid": "key-2025", "typ": typ });
    let input = format!("{}.{}", encode(&header), encode(claims));
    let signer =
        (DEFAULT_PROVIDER.signer_factory)(&jsonwebtoken::Algorithm::RS256, &key).expect("signer");
    let signature = signer.try_sign(input.as_bytes()).expect("signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// An ID token for `sub`, signed now, echoing `nonce`.
fn id_token(sub: &str, nonce: &str) -> String {
    let now = Utc::now().timestamp();
    let mut claims = token_case("id-valid").json["expected"]["ok"].clone();
    claims["sub"] = json!(sub);
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + 300);
    claims["auth_time"] = json!(now);
    claims["nonce"] = json!(nonce);
    sign(&claims, "JWT")
}

/// The test client, confidential.
fn client(issuer: &Issuer) -> crate::Client {
    issuer.client(ClientConfig {
        client_id: CLIENT.parse::<ClientId>().expect("client ID"),
        credentials: Credentials::Secret("secret".to_owned().into()),
        redirect_uri: "https://notes.example.com/auth/callback"
            .parse()
            .expect("callback"),
    })
}

/// An app whose home page shows the session's access token, with `routes` changing
/// its login routes.
fn login_app_with(issuer: &Issuer, routes: impl FnOnce(LoginRoutes) -> LoginRoutes) -> Router {
    let key = CookieKey::generate().expect("cookie key");
    let auth = routes(LoginRoutes::new(client(issuer), key).expect("a confidential client"));
    Router::new()
        .route(
            "/",
            get(|user: SignedIn| async move { user.login().access_token().expose().to_owned() }),
        )
        .route(
            "/both",
            get(
                |user: SignedIn, MaybeSignedIn(again): MaybeSignedIn| async move {
                    let again = again.expect("the same session");
                    format!(
                        "{} {}",
                        user.login().access_token().expose(),
                        again.login().access_token().expose()
                    )
                },
            ),
        )
        .nest(
            "/app",
            Router::new().route("/notes", get(|_: SignedIn| async {})),
        )
        .route(
            "/notes",
            post(|_: SignedIn| async {}).delete(|_: SignedIn| async {}),
        )
        .route("/maybe", post(|_: MaybeSignedIn| async {}))
        .route("/widget", post(|_: CrossOrigin<SignedIn>| async {}))
        .route(
            "/maybe-widget",
            post(|_: CrossOrigin<MaybeSignedIn>| async {}),
        )
        .nest("/auth", auth.router())
        .layer(auth.layer())
}

/// [`login_app_with`] the default login routes.
fn login_app(issuer: &Issuer) -> Router {
    login_app_with(issuer, |routes| routes)
}

/// A login started at `/auth/login`: its cookie's name and `name=value` pair, and the
/// `state` and `nonce` its redirect to auth carries.
struct Started {
    /// The pending login's cookie name: its slot.
    name: String,
    /// The pending login's cookie.
    cookie: String,
    /// The login's `state`.
    state: String,
    /// The login's `nonce`.
    nonce: String,
}

/// The cookie prefix of the test client's pending logins.
const PENDING_COOKIE: &str = "__Host-piquel-notes-web-login-";

impl Started {
    /// Starts a login returning to `return_to`, in a browser holding `cookies`.
    async fn at(app: &Router, return_to: &str, cookies: &[String]) -> Self {
        let path = format!("/auth/login?return_to={return_to}");
        let cookies = cookies.join("; ");
        let headers: &[_] = if cookies.is_empty() {
            &[]
        } else {
            &[(header::COOKIE, cookies.as_str())]
        };
        let response = get_with(app, &path, headers).await;
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
        assert!(
            parameter("scope")
                .split(' ')
                .any(|scope| scope == "offline_access"),
            "every login asks for a refresh token"
        );
        let [set] = &set_cookies(&response)[..] else {
            panic!("one pending login cookie");
        };
        assert!(set.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"));
        let cookie = set.split(';').next().expect("pair").to_owned();
        let (name, _) = cookie.split_once('=').expect("name=value");
        assert!(
            ["0", "1", "2"]
                .map(|slot| format!("{PENDING_COOKIE}{slot}"))
                .contains(&name.to_owned()),
            "{name}"
        );
        Self {
            name: name.to_owned(),
            cookie: cookie.clone(),
            state: parameter("state"),
            nonce: parameter("nonce"),
        }
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
}

/// Signs `sub` in to `app`; returns the session cookie's `name=value` pair.
async fn sign_in(app: &Router, sub: &str) -> String {
    let login = Started::at(app, "%2F", &[]).await;
    let response = login
        .complete(app, sub, std::slice::from_ref(&login.cookie))
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "signed in");
    set_cookie(&response, SESSION_COOKIE).expect("a session cookie")
}
