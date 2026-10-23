//! Bearer rejections against the shared challenge vectors, the session layer's
//! refresh lease, logout, and back-channel logout.

use super::session::{Lease, LeaseId, Session, SessionKey, Sessions};
use super::*;
use crate::{
    AuthenticationPolicy, ClientConfig, ClientId, Credentials, Issuer, KeyCache, KeySet, Resource,
    SessionId, StepUpRequirement, SystemClock,
    http::Http,
    tests::{Case, issuer, vector_token},
};
use ::axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
    routing::get,
};
use base64::Engine as _;
use chrono::{TimeDelta, Utc};
use piquel_common::{
    DeliveryId,
    protocol::{
        challenge::BearerChallenge,
        claims::{Absent, Audience, LogoutEvents, LogoutTokenClaims},
        metadata::ServerMetadata,
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

/// The status and header of a challenge vector, without its `error_description`,
/// which the extractors do not send.
fn expected(name: &str) -> (StatusCode, String) {
    let case = Case::all("challenges")
        .into_iter()
        .find(|case| case.name.ends_with(&format!("/{name}.json")))
        .expect("challenge vector");
    let challenge: BearerChallenge =
        serde_json::from_value(case.input("challenge").clone()).expect("vector challenge");
    let challenge = BearerChallenge {
        error_description: None,
        ..challenge
    };
    let status = StatusCode::from_u16(challenge.status()).expect("status");
    (status, challenge.to_string())
}

/// The response's status and `WWW-Authenticate` value.
fn challenge(response: &Response) -> (StatusCode, String) {
    let header = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().expect("text").to_owned())
        .unwrap_or_default();
    (response.status(), header)
}

/// Routes behind a bearer layer for `resource`, at the vectors' clock.
fn bearer_app(resource: Resource) -> Router {
    let validator = issuer(&token_case("access-valid")).resource(resource);
    Router::new()
        .route("/me", get(|_: Authenticated| async {}))
        .route("/public", get(|| async {}))
        .route("/read", get(|_: Scoped<notes::Read>| async {}))
        .route("/write", get(|_: Scoped<notes::Write>| async {}))
        .route(
            "/edit",
            get(|_: Scoped<(notes::Read, notes::Write)>| async {}),
        )
        .route("/all", get(|_: Scoped<notes::All>| async {}))
        .route(
            "/step-up",
            get(|_: RequireAuthentication<RecentPasskey>| async {}),
        )
        .layer(BearerLayer::new(validator))
}

/// Each rejection answers with the status and exact header of its challenge vector.
#[tokio::test]
async fn bearer_rejections_match_the_challenge_vectors() {
    let bearer = |name: &str| format!("Bearer {}", vector_token(name));
    let (valid, expired) = (bearer("access-valid"), bearer("access-expired"));
    let plain = bearer_app(Resource::new(RESOURCE).expect("resource"));
    let metadata = format!("{RESOURCE}/.well-known/oauth-protected-resource");
    let described = bearer_app(
        Resource::new(RESOURCE)
            .expect("resource")
            .with_metadata(metadata.parse().expect("metadata URL")),
    );

    let response = get_with(&plain, "/me", &[]).await;
    assert_eq!(challenge(&response), expected("missing-token"));
    let response = get_with(&described, "/read", &[]).await;
    assert_eq!(challenge(&response), expected("missing-token-scope"));
    for path in ["/edit", "/all"] {
        let response = get_with(&described, path, &[(header::AUTHORIZATION, &valid)]).await;
        assert_eq!(
            challenge(&response),
            expected("insufficient-scope"),
            "{path}"
        );
    }
    let response = get_with(&described, "/read", &[(header::AUTHORIZATION, &expired)]).await;
    assert_eq!(challenge(&response), expected("invalid-token"));
    let response = get_with(&described, "/step-up", &[(header::AUTHORIZATION, &valid)]).await;
    assert_eq!(
        challenge(&response),
        expected("insufficient-user-authentication")
    );
    let twice = [
        (header::AUTHORIZATION, valid.as_str()),
        (header::AUTHORIZATION, &valid),
    ];
    let response = get_with(&plain, "/me", &twice).await;
    assert_eq!(challenge(&response), expected("invalid-request"));
    let response = get_with(&plain, "/me", &[(header::AUTHORIZATION, "Bearer")]).await;
    assert_eq!(challenge(&response), expected("invalid-request"));
    // Only the extractors reject a malformed header: public routes still answer.
    for headers in [&twice[..], &[(header::AUTHORIZATION, "Bearer")]] {
        let response = get_with(&plain, "/public", headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    // Other schemes are not bearer tokens: the request has none.
    let response = get_with(&plain, "/me", &[(header::AUTHORIZATION, "Basic abc")]).await;
    assert_eq!(challenge(&response), expected("missing-token"));

    let response = get_with(&plain, "/read", &[(header::AUTHORIZATION, &valid)]).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// A read-only token is refused where writing is required, and the challenge names
/// the scope the handler enforces.
#[tokio::test]
async fn scoped_write_rejects_a_read_only_token() {
    let app = bearer_app(Resource::new(RESOURCE).expect("resource"));
    let token = format!("Bearer {}", vector_token("access-valid"));
    let response = get_with(&app, "/write", &[(header::AUTHORIZATION, &token)]).await;
    assert_eq!(
        challenge(&response),
        (
            StatusCode::FORBIDDEN,
            r#"Bearer error="insufficient_scope", scope="notes:write""#.to_owned()
        )
    );
}

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

/// A token endpoint answering refreshes after `delay`, counting them.
struct TokenEndpoint {
    /// The endpoint's URL.
    url: Url,
    /// Refreshes answered or in progress.
    calls: Arc<AtomicUsize>,
}

impl TokenEndpoint {
    /// Serves an endpoint that issues fresh tokens after `delay`.
    async fn start(delay: Duration) -> Self {
        Self::serve(delay, None).await
    }

    /// Serves an endpoint that refuses every refresh with `status` and `error`.
    async fn failing(status: StatusCode, error: &'static str) -> Self {
        Self::serve(Duration::ZERO, Some((status, error))).await
    }

    /// Serves the endpoint on a local port.
    async fn serve(delay: Duration, failure: Option<(StatusCode, &'static str)>) -> Self {
        use ::axum::response::IntoResponse;
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let router = Router::new().route(
            "/token",
            ::axum::routing::post(move || {
                let call = counted.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    tokio::time::sleep(delay).await;
                    if let Some((status, error)) = failure {
                        return (status, ::axum::Json(json!({ "error": error }))).into_response();
                    }
                    ::axum::Json(json!({
                        "access_token": format!("access-{call}"),
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "scope": "openid offline_access",
                        "refresh_token": format!("refresh-{call}"),
                    }))
                    .into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token endpoint");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move { ::axum::serve(listener, router).await });
        Self {
            url: format!("http://{address}/token").parse().expect("URL"),
            calls,
        }
    }
}

/// The vectors' issuer, with its token endpoint replaced and the system clock.
fn issuer_with_token_endpoint(token_endpoint: Url) -> Issuer {
    let discovery = Case::all("discovery")
        .into_iter()
        .find(|case| case.name.ends_with("/valid.json"))
        .expect("discovery vector");
    let mut metadata: ServerMetadata =
        serde_json::from_value(discovery.input("document").clone()).expect("metadata");
    metadata.token_endpoint = token_endpoint;
    let jwks = serde_json::to_vec(token_case("access-valid").input("jwks")).expect("JWKS");
    Issuer::with_keys(
        metadata,
        KeyCache::fixed(KeySet::parse(&jwks).expect("keys")),
        Http::default_client().expect("HTTP client"),
        Arc::new(SystemClock),
    )
}

/// An app whose home page shows the session's access token.
fn login_app(issuer: &Issuer, backend: &MemoryBackend) -> (Router, LoginRoutes) {
    let client = issuer.client(ClientConfig {
        client_id: CLIENT.parse::<ClientId>().expect("client ID"),
        credentials: Credentials::None,
        redirect_uri: "https://notes.example.com/auth/callback"
            .parse()
            .expect("callback"),
    });
    let auth = LoginRoutes::new(client, backend.clone());
    let app = Router::new()
        .route(
            "/",
            get(|user: SignedIn| async move { user.login().access_token.expose().to_owned() }),
        )
        .nest(
            "/app",
            Router::new().route("/notes", get(|_: SignedIn| async {})),
        )
        .nest("/auth", auth.router())
        .layer(auth.layer());
    (app, auth)
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

/// The fixture user's account ID.
const USER: &str = "01936f3e-8c00-7000-8000-000000000001";

/// A stored login whose ID token names `sub` and `sid`, its access token `expires_in`
/// seconds from now.
fn stored_login(sub: &str, sid: SessionId, expires_in: i64) -> StoredLogin {
    let mut claims = token_case("id-valid").json["expected"]["ok"].clone();
    claims["sub"] = json!(sub);
    claims["sid"] = json!(sid);
    serde_json::from_value(json!({
        "issuer": "https://auth.example.com",
        "id_token": { "claims": claims, "raw": "unused" },
        "access_token": "access-0",
        "expires_at": Utc::now() + TimeDelta::seconds(expires_in),
        "scopes": "openid offline_access",
        "refresh_token": "refresh-0",
    }))
    .expect("stored login")
}

/// Starts a session for `login` in `backend`; returns its key and cookie header.
async fn session(backend: &MemoryBackend, login: &StoredLogin) -> (SessionKey, String) {
    let key = SessionKey::generate().expect("key");
    let started = Sessions::new(backend.clone())
        .insert(&key, login, Utc::now() + TimeDelta::hours(1), Utc::now())
        .await
        .expect("insert session");
    assert!(started, "the session starts");
    let cookie = format!("__Host-piquel-session={}", key.as_cookie());
    (key, cookie)
}

/// The session under `key`, as the SDK reads it.
async fn load(backend: &MemoryBackend, key: &SessionKey) -> Option<Session> {
    Sessions::new(backend.clone())
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
            .refresh_token
            .as_ref()
            .map(crate::RefreshToken::expose),
        Some("refresh-1")
    );

    let (key, cookie) = session(&backend, &login).await;
    let refreshing = tokio::spawn({
        let app = app.clone();
        async move { get_with(&app, "/", &[(header::COOKIE, &cookie)]).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    Sessions::new(backend.clone())
        .delete(&key)
        .await
        .expect("logout");
    let response = refreshing.await.expect("request");
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "signed out");
    assert!(load(&backend, &key).await.is_none(), "not resurrected");
}

/// The lease is taken only at the version read, by one attempt at a time; only that
/// attempt can save; and a lease that expires unreleased marks the session abandoned.
#[tokio::test]
async fn leases_are_fenced() {
    let backend = MemoryBackend::default();
    let sessions = Sessions::new(backend.clone());
    let login = stored_login(USER, SessionId::new(), 300);
    let (key, _) = session(&backend, &login).await;
    let (first, second) = (
        LeaseId::generate().expect("lease"),
        LeaseId::generate().expect("lease"),
    );
    let minute = Duration::from_secs(60);
    let lease = |version, id, ttl| sessions.lease(&key, version, id, ttl, Utc::now());
    let save = |id| sessions.save(&key, id, login.clone(), Utc::now);
    assert!(matches!(
        lease(1, &first, minute).await.expect("lease"),
        Lease::Acquired(_)
    ));
    assert_eq!(lease(2, &second, minute).await.expect("lease"), Lease::Busy);
    assert!(
        save(&second).await.expect("save").is_none(),
        "not the holder"
    );
    let saved = save(&first).await.expect("save").expect("the holder saves");
    assert_eq!((saved.version, saved.leased), (3, false));
    assert!(save(&first).await.expect("save").is_none(), "given back");
    // A request that read version 1 must not redeem the token version 3 replaced.
    assert_eq!(
        lease(1, &second, minute).await.expect("lease"),
        Lease::Changed
    );
    assert!(matches!(
        lease(3, &second, Duration::ZERO).await.expect("lease"),
        Lease::Acquired(_)
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    // Past its expiry, even the holder cannot save: the lease may be found abandoned.
    assert!(save(&second).await.expect("save").is_none(), "expired");
    assert_eq!(
        lease(4, &first, minute).await.expect("lease"),
        Lease::Abandoned
    );
    sessions.delete(&key).await.expect("delete");
    assert_eq!(
        lease(4, &first, minute).await.expect("lease"),
        Lease::Missing
    );
}

/// A flaw of a [`Flawed`] backend.
#[derive(Clone, Copy)]
enum Flaw {
    /// Reads are slow.
    SlowReads,
    /// `replace` reads, pauses, then writes: not atomic.
    ReadThenWrite,
    /// `replace` inserts a missing record, which could resurrect a logged-out session.
    Upserting,
    /// `insert` replaces a record already there.
    Overwriting,
}

/// A memory backend with one flaw.
#[derive(Clone)]
struct Flawed(Flaw, MemoryBackend);

impl Flawed {
    /// An empty backend with `flaw`.
    fn new(flaw: Flaw) -> Self {
        Self(flaw, MemoryBackend::default())
    }
}

impl SessionBackend for Flawed {
    type Error = std::convert::Infallible;

    async fn load(&self, key: &str) -> Result<Option<SessionRecord>, Self::Error> {
        if matches!(self.0, Flaw::SlowReads) {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        self.1.load(key).await
    }

    async fn insert(&self, key: &str, record: &SessionRecord) -> Result<bool, Self::Error> {
        if matches!(self.0, Flaw::Overwriting) {
            self.1.remove(key).await?;
        }
        self.1.insert(key, record).await
    }

    async fn replace(
        &self,
        key: &str,
        expected: u64,
        record: &SessionRecord,
    ) -> Result<bool, Self::Error> {
        match self.0 {
            Flaw::ReadThenWrite => {
                let current = self.1.load(key).await?;
                std::thread::sleep(Duration::from_millis(2));
                if current.is_none_or(|stored| stored.version != expected) {
                    return Ok(false);
                }
                self.1.remove(key).await?;
                self.1.insert(key, record).await?;
                Ok(true)
            }
            Flaw::Upserting if self.1.load(key).await?.is_none() => {
                self.1.insert(key, record).await
            }
            _ => self.1.replace(key, expected, record).await,
        }
    }

    async fn remove(&self, key: &str) -> Result<bool, Self::Error> {
        self.1.remove(key).await
    }
}

/// A lease that expires while its save reads the session cannot save: the clock is
/// read again after the backend answers.
#[tokio::test]
async fn saves_recheck_expiry_after_slow_reads() {
    let sessions = Sessions::new(Flawed::new(Flaw::SlowReads));
    let login = stored_login(USER, SessionId::new(), 300);
    let key = SessionKey::generate().expect("key");
    sessions
        .insert(&key, &login, Utc::now() + TimeDelta::hours(1), Utc::now())
        .await
        .expect("insert");
    let lease = LeaseId::generate().expect("lease");
    let acquired = sessions
        .lease(&key, 1, &lease, Duration::from_millis(250), Utc::now())
        .await
        .expect("lease");
    assert!(matches!(acquired, Lease::Acquired(_)));
    // The lease is still valid when the save starts, but not once its read returns.
    let saved = sessions
        .save(&key, &lease, login, Utc::now)
        .await
        .expect("save");
    assert!(saved.is_none(), "an expired lease must not save");
}

/// The check refuses a non-atomic backend, one that creates records on `replace`,
/// one whose `insert` overwrites, and a runtime on which racing calls cannot overlap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_backend_catches_broken_backends() {
    for (flaw, broken) in [
        (
            Flaw::ReadThenWrite,
            "of racing replaces at one version, exactly one must write",
        ),
        (
            Flaw::Upserting,
            "replace wrote a record that does not exist",
        ),
        (Flaw::Overwriting, "insert replaced a record already there"),
    ] {
        assert!(matches!(
            check_backend(&Flawed::new(flaw)).await,
            Err(BackendCheckError::Contract(message)) if message == broken
        ));
    }
    // Neither a current-thread runtime nor a single worker lets racing calls overlap.
    for runtime in [
        tokio::runtime::Builder::new_current_thread().build(),
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build(),
    ] {
        let runtime = runtime.expect("runtime");
        let checked = tokio::task::spawn_blocking(move || {
            runtime.block_on(check_backend(&Flawed::new(Flaw::ReadThenWrite)))
        });
        assert!(matches!(
            checked.await.expect("task"),
            Err(BackendCheckError::Contract(message)) if message.contains("two workers")
        ));
    }
}

/// The memory backend keeps the backend contract, and a record the SDK cannot read
/// is a missing session, not a trusted one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_backend_keeps_the_contract() {
    let backend = MemoryBackend::default();
    check_backend(&backend).await.expect("a sound backend");
    let (key, _) = session(&backend, &stored_login(USER, SessionId::new(), 300)).await;
    let name = format!(
        "session-v2:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(key.as_cookie().as_bytes()))
    );
    let mut record = backend.load(&name).await.expect("load").expect("record");
    record.data = r#"{"not":"a session"}"#.into();
    assert!(backend.replace(&name, 1, &record).await.expect("replace"));
    assert!(load(&backend, &key).await.is_none());
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

/// Logout is accepted only from the app's own pages.
#[tokio::test]
async fn logout_refuses_other_origins() {
    let backend = MemoryBackend::default();
    let issuer = issuer_with_token_endpoint("http://127.0.0.1:9/token".parse().expect("URL"));
    let (app, _) = login_app(&issuer, &backend);
    let login = stored_login(
        "01936f3e-8c00-7000-8000-000000000001",
        SessionId::new(),
        300,
    );
    let (key, cookie) = session(&backend, &login).await;
    let logout = |origin: Option<&'static str>| {
        let (app, cookie) = (app.clone(), cookie.clone());
        async move {
            let mut request = Request::post("/auth/logout").header(header::COOKIE, cookie);
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            app.oneshot(request.body(Body::empty()).expect("request"))
                .await
                .expect("response")
                .status()
        }
    };
    for origin in [Some("https://evil.notes.example.com"), None] {
        assert_eq!(logout(origin).await, StatusCode::FORBIDDEN, "{origin:?}");
        assert!(load(&backend, &key).await.is_some());
    }
    assert_eq!(
        logout(Some("https://notes.example.com")).await,
        StatusCode::SEE_OTHER
    );
    assert!(load(&backend, &key).await.is_none());
}

/// Signs `claims` as auth signs logout tokens, with the vectors' `key-2025`.
fn logout_token(claims: &serde_json::Value) -> String {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, crypto::aws_lc::DEFAULT_PROVIDER};
    let pem = include_str!("../../../../tests/sdk-vectors/keys/key-2025.pem");
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
    let header = json!({ "alg": "RS256", "kid": "key-2025", "typ": "logout+jwt" });
    let input = format!("{}.{}", encode(&header), encode(claims));
    let signer =
        (DEFAULT_PROVIDER.signer_factory)(&jsonwebtoken::Algorithm::RS256, &key).expect("signer");
    let signature = signer.try_sign(input.as_bytes()).expect("signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

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
    logout_token(&serde_json::to_value(claims).expect("claims"))
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
    let started = Sessions::new(backend.clone())
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
