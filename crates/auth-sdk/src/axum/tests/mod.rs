//! Fixtures the axum integration's tests share: the vectors' issuer, a token
//! endpoint, an app behind the login layer, and stored sessions.

/// Back-channel logout.
mod backchannel;
/// Bearer rejections.
mod bearer;
/// Login routes and origin checks.
mod login;
/// Session refresh.
mod refresh;
/// The session store.
mod sessions;

use super::session::{Lease, LeaseId, Session, SessionKey, Sessions};
use super::*;
use crate::{
    AuthenticationPolicy, ClientConfig, ClientId, Credentials, Issuer, KeyCache, KeySet, Resource,
    SessionId, StepUpRequirement, SystemClock,
    http::Http,
    tests::{Case, issuer, metadata, serve, vector_token},
};
use ::axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use chrono::{TimeDelta, Utc};
use piquel_common::{
    DeliveryId,
    protocol::{
        challenge::BearerChallenge,
        claims::{Absent, Audience, LogoutEvents, LogoutTokenClaims},
    },
};
use serde_json::json;
use sha2::Digest as _;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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

/// A token vector case by name.
fn token_case(name: &str) -> Case {
    Case::all("tokens")
        .into_iter()
        .find(|case| case.name.ends_with(&format!("/{name}.json")))
        .expect("token vector")
}

/// Sends a `GET` with optional `Authorization` and `Cookie` values.
async fn get_with(app: &Router, path: &str, headers: &[(header::HeaderName, &str)]) -> Response {
    let mut request = Request::get(path);
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

/// A token endpoint on a local port, counting the requests it answers.
struct TokenEndpoint {
    /// The endpoint's URL.
    url: Url,
    /// Requests answered or in progress.
    calls: Arc<AtomicUsize>,
}

/// The form a token request posts.
type TokenForm = std::collections::HashMap<String, String>;

impl TokenEndpoint {
    /// Serves an endpoint that refreshes after `delay`, and redeems a code by issuing
    /// an ID token for the user and nonce the code names ([`code`]).
    async fn start(delay: Duration) -> Self {
        Self::answering(delay, |form, call| match form.get("code") {
            Some(code) => {
                let (sub, nonce) = code.split_once('.').expect("a code from `code`");
                let mut tokens = Self::tokens(call);
                tokens["id_token"] = json!(id_token(sub, nonce));
                ::axum::Json(tokens).into_response()
            }
            None => ::axum::Json(Self::tokens(call)).into_response(),
        })
        .await
    }

    /// Serves an endpoint that refuses every request with `status` and `error`.
    async fn failing(status: StatusCode, error: &'static str) -> Self {
        Self::answering(Duration::ZERO, move |_, _| {
            (status, ::axum::Json(json!({ "error": error }))).into_response()
        })
        .await
    }

    /// The tokens of the `call`th answer, without an ID token.
    fn tokens(call: usize) -> serde_json::Value {
        json!({
            "access_token": format!("access-{call}"),
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "openid offline_access",
            "refresh_token": format!("refresh-{call}"),
        })
    }

    /// Serves an endpoint answering each request with `answer`, after `delay`.
    async fn answering(
        delay: Duration,
        answer: impl Fn(TokenForm, usize) -> Response + Clone + Send + Sync + 'static,
    ) -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let router = Router::new().route(
            "/token",
            post(move |::axum::Form(form): ::axum::Form<TokenForm>| {
                let call = counted.fetch_add(1, Ordering::SeqCst) + 1;
                let answer = answer.clone();
                async move {
                    tokio::time::sleep(delay).await;
                    answer(form, call)
                }
            }),
        );
        let address = serve(router).await;
        Self {
            url: format!("http://{address}/token").parse().expect("URL"),
            calls,
        }
    }
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

/// The claims of the vectors' valid ID token, for `sub` and valid now.
fn id_claims(sub: &str) -> serde_json::Value {
    let now = Utc::now().timestamp();
    let mut claims = token_case("id-valid").json["expected"]["ok"].clone();
    claims["sub"] = json!(sub);
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + 300);
    claims["auth_time"] = json!(now);
    claims
}

/// An ID token for `sub`, signed now, echoing `nonce`.
fn id_token(sub: &str, nonce: &str) -> String {
    let mut claims = id_claims(sub);
    claims["nonce"] = json!(nonce);
    sign(&claims, "JWT")
}

/// The vectors' issuer, with its token endpoint replaced and the system clock.
fn issuer_with_token_endpoint(token_endpoint: Url) -> Issuer {
    let mut metadata = metadata();
    metadata.token_endpoint = token_endpoint;
    // Logins redirect at once, with the request in the URL.
    metadata.pushed_authorization_request_endpoint = None;
    let jwks = serde_json::to_vec(token_case("access-valid").input("jwks")).expect("JWKS");
    Issuer::with_keys(
        metadata,
        KeyCache::fixed(KeySet::parse(&jwks).expect("keys")),
        Http::default_client().expect("HTTP client"),
        Arc::new(SystemClock),
    )
}

/// A memory backend that remembers the key of every write, so tests can read all of
/// it back.
#[derive(Clone, Default)]
struct Spy {
    /// The records.
    records: MemoryBackend,
    /// Every key written.
    written: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
}

impl Spy {
    /// Every record still stored.
    async fn dump(&self) -> Vec<SessionRecord> {
        let keys = self.written.lock().expect("keys").clone();
        let mut records = Vec::new();
        for key in keys {
            records.extend(self.records.load(&key).await.expect("load"));
        }
        records
    }

    /// Notes a write to `key`.
    fn note(&self, key: &str) {
        self.written.lock().expect("keys").insert(key.to_owned());
    }
}

impl SessionBackend for Spy {
    type Error = std::convert::Infallible;

    async fn load(&self, key: &str) -> Result<Option<SessionRecord>, Self::Error> {
        self.records.load(key).await
    }

    async fn insert(&self, key: &str, record: &SessionRecord) -> Result<bool, Self::Error> {
        self.note(key);
        self.records.insert(key, record).await
    }

    async fn replace(
        &self,
        key: &str,
        expected: u64,
        record: &SessionRecord,
    ) -> Result<bool, Self::Error> {
        self.note(key);
        self.records.replace(key, expected, record).await
    }

    async fn remove(&self, key: &str) -> Result<bool, Self::Error> {
        self.records.remove(key).await
    }
}

/// An app whose home page shows the session's access token.
fn login_app(issuer: &Issuer, backend: &impl SessionBackend) -> (Router, LoginRoutes) {
    let client = issuer.client(ClientConfig {
        client_id: CLIENT.parse::<ClientId>().expect("client ID"),
        credentials: Credentials::None,
        redirect_uri: "https://notes.example.com/auth/callback"
            .parse()
            .expect("callback"),
    });
    let key = CookieKey::generate().expect("cookie key");
    let auth = LoginRoutes::new(client, backend.clone(), key);
    let app = Router::new()
        .route(
            "/",
            get(|user: SignedIn| async move { user.login().access_token().expose().to_owned() }),
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
        .layer(auth.layer());
    (app, auth)
}

/// The fixture user's account ID.
const USER: &str = "01936f3e-8c00-7000-8000-000000000001";

/// A stored login whose ID token names `sub` and `sid`, its access token `expires_in`
/// seconds from now.
fn stored_login(sub: &str, sid: SessionId, expires_in: i64) -> StoredLogin {
    let mut claims = id_claims(sub);
    claims["sid"] = json!(sid);
    let tokens = serde_json::from_value(json!({
        "id_token": { "claims": claims, "raw": "id-0" },
        "access_token": "access-0",
        "expires_at": Utc::now() + TimeDelta::seconds(expires_in),
        "scopes": "openid offline_access",
        "refresh_token": "refresh-0",
    }))
    .expect("tokens");
    StoredLogin::new("https://auth.example.com".into(), tokens).expect("an ID token")
}

/// The test client's sessions in `backend`.
fn sessions(backend: impl SessionBackend) -> Sessions {
    Sessions::new(backend, CLIENT.parse().expect("client ID"))
}

/// Starts a session for `login` in `backend`; returns its key and cookie header.
async fn session(backend: &impl SessionBackend, login: &StoredLogin) -> (SessionKey, String) {
    let key = SessionKey::generate().expect("key");
    let started = sessions(backend.clone())
        .insert(&key, login, Utc::now() + TimeDelta::hours(1), Utc::now())
        .await
        .expect("insert session");
    assert!(started, "the session starts");
    let cookie = format!("{SESSION_COOKIE}={}", key.as_cookie());
    (key, cookie)
}

/// The session under `key`, as the SDK reads it.
async fn load(backend: &impl SessionBackend, key: &SessionKey) -> Option<Session> {
    sessions(backend.clone())
        .load(key, Utc::now())
        .await
        .expect("load")
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
