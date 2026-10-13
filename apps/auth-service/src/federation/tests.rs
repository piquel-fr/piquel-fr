//! Federation protocol, browser-binding and transactional identity policy tests.

use super::{
    providers::{GoogleClaims, GoogleProtocol, IdentityStrategy, ProviderEndpoints},
    *,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
    routing::post,
};
use jsonwebtoken::{Algorithm, DecodingKey};
use piquel_common::SecretReference;
use piquel_crypto::Rs256Key;
use piquel_crypto::Secret;
use piquel_repository::{
    DatabaseConfig, DatabaseTransaction, InsertExternalIdentity, InsertPasskey, InsertUser,
    InsertVerifiedEmail,
};
use std::collections::HashMap;
use tower::ServiceExt;

/// Isolated database fixture with replaceable provider endpoints and unique subjects.
struct TestApp {
    /// Federation state whose back-channel requests use a local HTTP fixture.
    app: FederationApplication,
    /// Provider mock server, stopped when the fixture is dropped.
    task: tokio::task::JoinHandle<()>,
    /// Temporary provider secret deleted with the fixture.
    secret_file: std::path::PathBuf,
    /// Unique numeric subject returned by this fixture’s provider.
    subject: String,
}
impl Drop for TestApp {
    /// Stops the fixture server and attempts to remove its temporary secret.
    fn drop(&mut self) {
        self.task.abort();
        if let Err(error) = std::fs::remove_file(&self.secret_file) {
            tracing::warn!(%error, "could not remove federation fixture secret");
        }
    }
}
impl TestApp {
    /// Creates a provider fixture with no verified contact address.
    async fn new() -> Self {
        Self::with_email(None).await
    }
    /// Creates unique provider evidence with an optional verified primary address.
    async fn with_email(email: Option<&str>) -> Self {
        let url = piquel_common::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name an isolated migrated PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, StdDuration::from_secs(5))
                .expect("database configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let subject = u64::from_be_bytes(
            piquel_crypto::Secret::generate()
                .expect("random")
                .as_bytes()[..8]
                .try_into()
                .expect("eight bytes"),
        )
        .max(1);
        let emails = email.map_or_else(
            || serde_json::json!([]),
            |email| serde_json::json!([{"email":email,"primary":true,"verified":true}]),
        );
        let mock = Router::new()
            .route(
                "/token",
                post(|| async { Json(serde_json::json!({"access_token":"mock-token"})) }),
            )
            .route(
                "/user",
                get(move || async move {
                    Json(serde_json::json!({"id":subject,"name":"Social User","login":"social"}))
                }),
            )
            .route(
                "/emails",
                get(move || {
                    let emails = emails.clone();
                    async move { Json(emails) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let base = format!("http://{}", listener.local_addr().expect("mock address"));
        let task = tokio::spawn(async move {
            axum::serve(listener, mock).await.expect("mock server");
        });
        let secret_file =
            std::env::temp_dir().join(format!("piquel-federation-test-{}", TokenId::new()));
        std::fs::write(&secret_file, "test-secret").expect("mock provider secret");
        let config = ProviderConfig {
            client_id: "test-client".into(),
            client_secret: SecretReference::parse(&format!("file://{}", secret_file.display()))
                .expect("secret reference"),
        };
        let mut app = FederationApplication::new(
            database,
            &FederationConfig {
                origin: "https://auth.piquel.fr/"
                    .parse::<piquel_common::Origin>()
                    .expect("origin"),
                settings_url: "https://piquel.fr/settings"
                    .parse::<piquel_common::PublicUrl>()
                    .expect("settings"),
                providers: BTreeMap::from([(Provider::GitHub, config)]),
            },
        )
        .expect("federation");
        let endpoints = app
            .endpoints
            .get_mut(&Provider::GitHub)
            .expect("GitHub facts");
        endpoints.token = format!("{base}/token");
        match &mut endpoints.identity {
            IdentityStrategy::GitHub(protocol) => {
                protocol.user = format!("{base}/user");
                protocol.emails = format!("{base}/emails");
            }
            IdentityStrategy::Google(_) => panic!("GitHub must use OAuth profile fetching"),
        }
        Self {
            app,
            task,
            secret_file,
            subject: subject.to_string(),
        }
    }
    /// Runs a complete GitHub authorization start and bound callback.
    async fn callback(&self) -> Response {
        let router = self.app.clone().routes();
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::POST,
                "/login/github/start",
                None,
                &serde_json::json!({}),
            ))
            .await
            .expect("start");
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("pair")
            .to_owned();
        let body = TestApp::json(response).await;
        let url = Url::parse(body["redirect_url"].as_str().expect("redirect")).expect("url");
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .expect("state")
            .1
            .into_owned();
        router
            .oneshot(TestApp::request(
                Method::GET,
                &format!("/login/github/callback?state={state}&code=mock-code"),
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("callback")
    }
    /// Creates a unique account with optional verified email and passkey.
    async fn user(&self, email: Option<&str>, with_key: bool) -> UserId {
        let id = UserId::new();
        let mut tx = self.app.database.begin().await.expect("transaction");
        tx.users()
            .insert(&InsertUser {
                id,
                username: format!("fed_{}", TokenId::new()).replace('-', ""),
                display_name: "Federation Test".into(),
            })
            .await
            .expect("user");
        if let Some(email) = email {
            tx.emails()
                .insert_verified(&InsertVerifiedEmail {
                    id: TokenId::new(),
                    user_id: id,
                    normalized_email: email.into(),
                    is_primary: true,
                    verified_at: Utc::now(),
                })
                .await
                .expect("email");
        }
        if with_key {
            self.key(&mut tx, id).await;
        }
        tx.commit().await.expect("commit");
        id
    }
    /// Adds passkey-presence evidence; ceremony cryptography is covered by passkey tests.
    async fn key(&self, tx: &mut DatabaseTransaction<'_>, user_id: UserId) {
        // Federation only checks key presence; cryptographic ceremony coverage lives in passkey tests.
        tx.passkeys()
            .insert(&InsertPasskey {
                id: TokenId::new(),
                credential_id: TokenId::new().to_string().into_bytes(),
                user_id,
                credential: serde_json::json!({}),
                friendly_name: "Existing key".into(),
            })
            .await
            .expect("key");
    }
    /// Stores browser-bound evidence optionally targeting an existing account.
    async fn pending(
        &self,
        owner: Option<UserId>,
        email: Option<&str>,
    ) -> (PendingFederation, HeaderMap) {
        let secret = Secret::generate().expect("browser secret");
        let pending = PendingFederation {
            id: TokenId::new(),
            browser_digest: secret.digest().as_bytes().to_vec(),
            provider: piquel_auth_protocol::Provider::GitHub,
            issuer: ProviderEndpoints::new(Provider::GitHub).issuer.into(),
            subject: TokenId::new().to_string(),
            email: email.map(str::to_owned),
            display_name: "New social account".into(),
            return_to: "/".into(),
            link_user_id: owner,
            link_session_id: None,
            expires_at: Utc::now() + Duration::minutes(5),
        };
        self.app
            .database
            .federation()
            .insert_pending(&pending)
            .await
            .expect("pending identity");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}={}",
                BrowserCookie::FederationPending.as_str(),
                secret.encoded()
            ))
            .expect("cookie"),
        );
        (pending, headers)
    }
    /// Creates a browser session and optionally grants passkey management access.
    async fn session(&self, user_id: UserId, grant: bool) -> (SessionId, String) {
        let mut tx = self.app.database.begin().await.expect("transaction");
        let cookie = security::Session::create(&mut tx, user_id, AuthenticationMethod::Federation)
            .await
            .expect("session");
        let raw = format!("{}={}", BrowserCookie::Session.as_str(), cookie.encoded());
        tx.commit().await.expect("commit");
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&raw).expect("cookie"));
        let session = security::Session::required(&self.app.database, &headers)
            .await
            .expect("active session");
        if grant {
            self.app
                .database
                .sessions()
                .grant_management(session.id)
                .await
                .expect("grant");
        }
        (session.id, raw)
    }
    /// Borrows Google's replaceable verification facts from the fixture.
    fn google_protocol(&self) -> &GoogleProtocol {
        match &self.app.endpoints[&Provider::Google].identity {
            IdentityStrategy::Google(protocol) => protocol,
            IdentityStrategy::GitHub(_) => panic!("Google must use signed ID tokens"),
        }
    }

    /// Builds a JSON HTTP request with an optional browser-cookie header.
    fn request(
        method: Method,
        path: &str,
        cookie: Option<&str>,
        body: &serde_json::Value,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request.body(Body::from(body.to_string())).expect("request")
    }
    /// Reads a bounded response body and parses the fixture’s JSON.
    async fn json(response: Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.expect("body"))
            .expect("JSON")
    }
}
/// Rejects unsafe continuations and duplicated pending-browser cookies.
#[test]
fn return_destinations_and_browser_bindings_are_strict() {
    let settings = Url::parse("https://preview.example/settings").expect("settings");
    for path in [
        "//evil.test",
        "/\\evil.test",
        "https://evil.test",
        "/login#x",
        "/\n/evil",
    ] {
        assert!(ReturnTo::parse(Some(path), &settings).is_err(), "{path}");
    }
    assert_eq!(
        ReturnTo::parse(Some("/oauth/authorize?request=abc"), &settings)
            .expect("local return")
            .0,
        "/oauth/authorize?request=abc"
    );
    assert_eq!(
        ReturnTo::parse(None, &settings).expect("default return").0,
        DEFAULT_RETURN_TO
    );
    assert_eq!(
        ReturnTo::parse(Some(settings.as_str()), &settings)
            .expect("settings return")
            .0,
        settings.as_str()
    );
    assert!(ReturnTo::parse(Some("https://piquel.fr/settings"), &settings).is_err());
    assert!(
        ReturnTo::parse(
            Some(&format!("/{}", "x".repeat(MAX_RETURN_TO_BYTES))),
            &settings
        )
        .is_err()
    );
    let secret = Secret::generate().expect("browser secret");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{0}={1}; {0}={1}",
            BrowserCookie::FederationPending.as_str(),
            secret.encoded()
        ))
        .expect("cookie"),
    );
    assert!(BrowserCookie::FederationPending.read(&headers).is_none());
}

/// Callbacks require browser state and retain unregistered subjects as pending evidence.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn provider_mock_callback_requires_browser_state_and_stays_pending() {
    let test = TestApp::new().await;
    let router = test.app.clone().routes();
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::POST,
            "/login/github/start",
            None,
            &serde_json::json!({}),
        ))
        .await
        .expect("start");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("cookie")
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let body = TestApp::json(response).await;
    let url = Url::parse(body["redirect_url"].as_str().expect("redirect")).expect("url");
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .expect("state")
        .1
        .into_owned();
    let path = format!("/login/github/callback?code=mock-code&state={state}");
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::GET,
            &path,
            None,
            &serde_json::Value::Null,
        ))
        .await
        .expect("unbound callback");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::GET,
            &path,
            Some(&cookie),
            &serde_json::Value::Null,
        ))
        .await
        .expect("callback");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login?social=signup");
    assert!(
        !response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value
                .to_str()
                .expect("cookie")
                .starts_with("__Host-piquel_session="))
    );
    let response = router
        .oneshot(TestApp::request(
            Method::GET,
            &path,
            Some(&cookie),
            &serde_json::Value::Null,
        ))
        .await
        .expect("replay");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Signup must create its first passkey and cannot claim an existing account’s email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn onboarding_commits_only_with_first_key_and_browser_and_never_claims_existing_email() {
    let test = TestApp::new().await;
    let (pending, headers) = test.pending(None, None).await;
    assert!(
        FederationApplication::pending_signup(&test.app.database, &headers, TokenId::new())
            .await
            .is_err(),
        "registration must name the displayed pending signup"
    );
    FederationApplication::pending_signup(&test.app.database, &headers, pending.id)
        .await
        .expect("pending signup");
    let user = test.user(None, false).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        FederationApplication::attach_signup(&mut tx, pending.id, &headers, user)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
    let mut tx = test.app.database.begin().await.expect("tx");
    test.key(&mut tx, user).await;
    assert!(
        FederationApplication::attach_signup(&mut tx, pending.id, &HeaderMap::new(), user)
            .await
            .is_err()
    );
    FederationApplication::attach_signup(&mut tx, pending.id, &headers, user)
        .await
        .expect("first key authorizes signup");
    tx.commit().await.expect("commit");
    assert_eq!(
        test.app
            .database
            .federation()
            .find_active(&pending.issuer, &pending.subject)
            .await
            .expect("identity")
            .expect("linked")
            .user_id,
        user
    );
    let email = format!("{}@example.com", TokenId::new());
    test.user(Some(&email), true).await;
    let (pending, headers) = test.pending(None, Some(&email)).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        FederationApplication::attach_signup(&mut tx, pending.id, &headers, user)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
}

/// Linking requires the intended account’s grant; unlink frees the subject and preserves email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn linking_requires_target_grant_and_unlink_releases_subject_without_changing_email() {
    let test = TestApp::new().await;
    let email = format!("{}@example.com", TokenId::new());
    let target = test.user(Some(&email), true).await;
    let other = test.user(None, true).await;
    let observed = format!("{}@example.com", TokenId::new());
    let (pending, pending_headers) = test.pending(Some(target), Some(&observed)).await;
    let (_, other_cookie) = test.session(other, true).await;
    let (target_session, target_cookie) = test.session(target, false).await;
    let (other_session, _) = test.session(target, false).await;
    let pending_cookie = pending_headers[header::COOKIE]
        .to_str()
        .expect("pending cookie");
    let router = test.app.clone().routes();
    for cookie in [&other_cookie, &target_cookie] {
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::POST,
                "/login/social/link",
                Some(&format!("{cookie}; {pending_cookie}")),
                &serde_json::json!({}),
            ))
            .await
            .expect("link rejection");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    test.app
        .database
        .sessions()
        .grant_management(target_session)
        .await
        .expect("grant");
    let response = router
        .clone()
        .oneshot(TestApp::request(
            Method::POST,
            "/login/social/link",
            Some(&format!("{target_cookie}; {pending_cookie}")),
            &serde_json::json!({}),
        ))
        .await
        .expect("link");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        test.app
            .database
            .sessions()
            .find_active_by_id(other_session)
            .await
            .expect("other session")
            .is_some()
    );
    assert_eq!(
        test.app
            .database
            .emails()
            .find_active_verified(&email)
            .await
            .expect("email")
            .expect("owner")
            .user_id,
        target
    );
    assert!(
        test.app
            .database
            .emails()
            .find_active_verified(&observed)
            .await
            .expect("observation")
            .is_none()
    );
    let response = router
        .oneshot(TestApp::request(
            Method::DELETE,
            "/account/social-identities/github",
            Some(&target_cookie),
            &serde_json::json!({}),
        ))
        .await
        .expect("unlink");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        test.app
            .database
            .sessions()
            .find_active_by_id(other_session)
            .await
            .expect("revoked other session")
            .is_none()
    );
    test.app
        .database
        .federation()
        .insert_identity(&FederationApplication::identity(&pending, other))
        .await
        .expect("unlinked subject reusable");
}

/// Google evidence requires trusted signatures and claims but does not require email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn google_mock_validates_signature_audience_nonce_and_expiry_without_requiring_email() {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut test = TestApp::new().await;
    let rsa = Rs256Key::generate("google-test").expect("RSA test key");
    let encoding =
        EncodingKey::from_rsa_pem(&rsa.private_key_pem().expect("PEM")).expect("JWT key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("google-test".into());
    let mut claims = serde_json::json!({"iss":"https://accounts.google.com","sub":"12345","aud":"test-client","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+300,"nonce":"test-nonce"});
    let valid = encode(&header, &claims, &encoding).expect("signed token");
    claims["aud"] = serde_json::json!("another-client");
    let wrong_audience = encode(&header, &claims, &encoding).expect("signed token");
    claims["aud"] = serde_json::json!("test-client");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() - 120);
    let expired = encode(&header, &claims, &encoding).expect("signed token");
    let other_rsa = Rs256Key::generate("google-test").expect("untrusted key");
    let other_encoding =
        EncodingKey::from_rsa_pem(&other_rsa.private_key_pem().expect("PEM")).expect("JWT key");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() + 300);
    let wrong_signature =
        encode(&header, &claims, &other_encoding).expect("untrusted signed token");
    let keys = rsa.jwks();
    let tokens = Arc::new(HashMap::from([
        ("valid".to_owned(), valid),
        ("wrong-audience".to_owned(), wrong_audience),
        ("expired".to_owned(), expired),
        ("wrong-signature".to_owned(), wrong_signature),
    ]));
    let mock = Router::new()
        .route(
            "/keys",
            get(move || {
                let keys = keys.clone();
                async move { Json(keys) }
            }),
        )
        .route(
            "/token/{kind}",
            get(move |Path(kind): Path<String>| {
                let tokens = tokens.clone();
                async move { Json(serde_json::json!({"id_token":tokens[&kind]})) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock listener");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, mock).await.expect("mock server");
    });
    match &mut test
        .app
        .endpoints
        .get_mut(&Provider::Google)
        .expect("Google facts")
        .identity
    {
        IdentityStrategy::Google(protocol) => protocol.keys = format!("{base}/keys"),
        IdentityStrategy::GitHub(_) => panic!("Google must use signed ID tokens"),
    }
    let response = test
        .app
        .client
        .get(format!("{base}/token/valid"))
        .send()
        .await
        .expect("valid response");
    let identity = test
        .app
        .google_identity(
            response,
            "test-client",
            "test-nonce",
            test.google_protocol(),
        )
        .await
        .expect("valid Google identity without email");
    assert_eq!(identity.subject, "12345");
    assert!(identity.email.is_none());
    for (kind, nonce, expected) in [
        ("valid", "wrong-nonce", "nonce does not match"),
        ("wrong-audience", "test-nonce", "failed verification"),
        ("expired", "test-nonce", "failed verification"),
        ("wrong-signature", "test-nonce", "failed verification"),
    ] {
        let response = test
            .app
            .client
            .get(format!("{base}/token/{kind}"))
            .send()
            .await
            .expect("mock response");
        let error = test
            .app
            .google_identity(response, "test-client", nonce, test.google_protocol())
            .await
            .err()
            .expect("rejected");
        assert!(error.to_string().contains(expected), "{kind}: {error}");
    }
    task.abort();
}

/// Stable provider subjects take priority over email observations and require an existing passkey.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn callback_email_collision_never_links_and_known_subject_never_bootstraps_a_missing_key() {
    let observed = format!("{}@example.com", TokenId::new());
    let original = format!("{}@example.com", TokenId::new());
    let test = TestApp::with_email(Some(&observed)).await;
    let email_owner = test.user(Some(&observed), true).await;
    let response = test.callback().await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login?social=link");
    assert!(
        test.app
            .database
            .federation()
            .find_active(
                ProviderEndpoints::new(Provider::GitHub).issuer,
                &test.subject
            )
            .await
            .expect("identity")
            .is_none()
    );
    let subject_owner = test.user(Some(&original), false).await;
    test.app
        .database
        .federation()
        .insert_identity(&InsertExternalIdentity {
            id: TokenId::new(),
            user_id: subject_owner,
            provider: piquel_auth_protocol::Provider::GitHub,
            issuer: ProviderEndpoints::new(Provider::GitHub).issuer.into(),
            subject: test.subject.clone(),
            linked_email: Some(original.clone()),
        })
        .await
        .expect("known identity");
    let response = test.callback().await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "known accounts cannot bootstrap from social login"
    );
    let mut tx = test.app.database.begin().await.expect("tx");
    test.key(&mut tx, subject_owner).await;
    tx.commit().await.expect("commit");
    let response = test.callback().await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/");
    let session_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("cookie"))
        .find(|cookie| cookie.starts_with("__Host-piquel_session="))
        .expect("session cookie")
        .split(';')
        .next()
        .expect("cookie pair");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(session_cookie).expect("cookie"),
    );
    let session = security::Session::required(&test.app.database, &headers)
        .await
        .expect("social session");
    assert_eq!(
        session.user_id, subject_owner,
        "stable subject takes priority over email observation"
    );
    assert!(
        security::Session::management(&test.app.database, &headers)
            .await
            .is_err()
    );
    assert_eq!(
        test.app
            .database
            .emails()
            .find_active_verified(&original)
            .await
            .expect("original email")
            .expect("owner")
            .user_id,
        subject_owner
    );
    assert_eq!(
        test.app
            .database
            .emails()
            .find_active_verified(&observed)
            .await
            .expect("observed email")
            .expect("owner")
            .user_id,
        email_owner
    );
}

/// ID-token verification rejects malformed claims, untrusted issuers and additional audiences.
#[test]
fn google_signed_tokens_require_well_typed_trusted_issuer_and_audience() {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let rsa = Rs256Key::generate("google-test").expect("RSA key");
    let encoding =
        EncodingKey::from_rsa_pem(&rsa.private_key_pem().expect("PEM")).expect("encoding key");
    let decoding =
        DecodingKey::from_rsa_pem(&rsa.public_key_pem().expect("PEM")).expect("decoding key");
    let header = Header::new(Algorithm::RS256);
    let valid = serde_json::json!({"iss":"https://accounts.google.com","aud":"client","sub":"subject","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+300,"nonce":"nonce"});
    let verify = |claims: &serde_json::Value| {
        GoogleClaims::verify(
            &encode(&header, claims, &encoding).expect("signed token"),
            &decoding,
            "client",
            "nonce",
            match &ProviderEndpoints::new(Provider::Google).identity {
                IdentityStrategy::Google(protocol) => protocol.issuers,
                IdentityStrategy::GitHub(_) => panic!("Google must use signed ID tokens"),
            },
        )
    };
    assert!(verify(&valid).is_ok());
    for field in ["iss", "aud", "exp", "sub"] {
        let mut claims = valid.clone();
        claims.as_object_mut().expect("object").remove(field);
        assert!(verify(&claims).is_err(), "missing {field}");
        for value in [
            serde_json::Value::Null,
            serde_json::json!(123),
            serde_json::json!({}),
        ] {
            claims[field] = value;
            // Numeric expiry is valid only while it lies in the future; 123 is expired.
            assert!(verify(&claims).is_err(), "invalid {field}");
        }
    }
    for audience in [
        serde_json::json!([]),
        serde_json::json!(["client", "untrusted"]),
        serde_json::json!(["client", 123]),
        serde_json::json!("other"),
    ] {
        let mut claims = valid.clone();
        claims["aud"] = audience;
        assert!(verify(&claims).is_err());
    }
    let mut claims = valid.clone();
    claims["aud"] = serde_json::json!(["client"]);
    assert!(verify(&claims).is_ok());
    claims["iss"] = serde_json::json!("https://untrusted.example");
    assert!(verify(&claims).is_err());
    claims = valid;
    claims["azp"] = serde_json::json!("other");
    assert!(verify(&claims).is_err());
}

/// Local Google key endpoint: the first response publishes key `a`, the second keys `a`
/// and `b` (a rotation), and later ones fail as an outage would.
struct GoogleKeysMock {
    /// Google facts whose key endpoint is this mock.
    protocol: GoogleProtocol,
    /// Number of key requests served so far.
    requests: Arc<std::sync::atomic::AtomicUsize>,
    /// Mock server, stopped when the fixture is dropped.
    task: tokio::task::JoinHandle<()>,
}
impl Drop for GoogleKeysMock {
    /// Stops the mock server.
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl GoogleKeysMock {
    /// How long the mock's responses let keys stay fresh.
    const MAX_AGE: StdDuration = StdDuration::from_secs(600);

    /// Serves the key endpoint on a local port.
    async fn start() -> Self {
        let keys = |kids: &[&str]| {
            let keys: Vec<_> = kids
                .iter()
                .map(|kid| Rs256Key::generate(*kid).expect("RSA key").jwks()["keys"][0].clone())
                .collect();
            serde_json::json!({ "keys": keys })
        };
        let responses = Arc::new([keys(&["a"]), keys(&["a", "b"])]);
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = requests.clone();
        let mock = Router::new().route(
            "/keys",
            get(move || async move {
                let request = served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let cache_control = format!("public, max-age={}", Self::MAX_AGE.as_secs());
                match responses.get(request) {
                    Some(keys) => ([(header::CACHE_CONTROL, cache_control)], Json(keys.clone()))
                        .into_response(),
                    None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let task = tokio::spawn(async move {
            axum::serve(listener, mock).await.expect("mock server");
        });
        let IdentityStrategy::Google(mut protocol) =
            ProviderEndpoints::new(Provider::Google).identity
        else {
            panic!("Google must use signed ID tokens");
        };
        protocol.keys = format!("{base}/keys");
        Self {
            protocol,
            requests,
            task,
        }
    }

    /// Number of key requests served so far.
    fn requests(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Looks up `kid` at `elapsed` after `start`, as one sign-in would.
    async fn key(
        &self,
        kid: &str,
        start: std::time::Instant,
        elapsed: u64,
    ) -> Result<DecodingKey, providers::ProviderError> {
        self.protocol
            .signing_key(
                &reqwest::Client::new(),
                kid.into(),
                start + StdDuration::from_secs(elapsed),
            )
            .await
    }
}

/// Concurrent and later sign-ins share one key fetch until `max-age` runs out, and an
/// outage keeps the cached keys instead of retrying on every sign-in.
#[tokio::test]
async fn google_keys_are_cached_until_max_age_and_survive_an_outage() {
    let mock = GoogleKeysMock::start().await;
    let start = std::time::Instant::now();
    let max_age = GoogleKeysMock::MAX_AGE.as_secs();
    let mut sign_ins = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let protocol = mock.protocol.clone();
        sign_ins.spawn(async move {
            protocol
                .signing_key(&reqwest::Client::new(), "a".into(), start)
                .await
                .map(drop)
        });
    }
    while let Some(result) = sign_ins.join_next().await {
        result.expect("sign-in task").expect("key a");
    }
    assert_eq!(mock.requests(), 1, "concurrent sign-ins share one fetch");
    mock.key("a", start, max_age - 1)
        .await
        .expect("cached key a");
    assert_eq!(mock.requests(), 1, "fresh keys are reused");
    mock.key("a", start, max_age)
        .await
        .expect("refetched key a");
    assert_eq!(mock.requests(), 2, "expired keys are refetched");
    mock.key("a", start, 2 * max_age)
        .await
        .expect("stale key a during an outage");
    assert_eq!(mock.requests(), 3, "expired keys are refetched");
    mock.key("a", start, 2 * max_age + 1)
        .await
        .expect("stale key a during an outage");
    assert_eq!(mock.requests(), 3, "a failed fetch is not retried at once");
}

/// An unknown key ID refetches once, so rotated keys are found, but never more than once
/// a minute, so bogus key IDs cannot make every sign-in call Google.
#[tokio::test]
async fn unknown_google_key_ids_refetch_at_most_once_a_minute() {
    let mock = GoogleKeysMock::start().await;
    let start = std::time::Instant::now();
    mock.key("a", start, 0).await.expect("key a");
    let error = mock
        .key("b", start, 59)
        .await
        .err()
        .expect("b not fetched yet");
    assert!(error.to_string().contains("no RSA signing key"), "{error}");
    assert_eq!(mock.requests(), 1, "refetches wait a minute");
    mock.key("b", start, 60).await.expect("rotated key b");
    assert_eq!(mock.requests(), 2, "an unknown key ID refetches once");
    for elapsed in [60, 90, 119] {
        mock.key("bogus", start, elapsed)
            .await
            .err()
            .expect("bogus key");
    }
    assert_eq!(mock.requests(), 2, "bogus key IDs wait for the interval");
    mock.key("bogus", start, 120)
        .await
        .err()
        .expect("bogus key");
    mock.key("bogus", start, 121)
        .await
        .err()
        .expect("bogus key");
    assert_eq!(mock.requests(), 3, "at most one refetch per interval");
    mock.key("a", start, 121).await.expect("cached key a");
}

/// Resolved credentials fail at startup with variable context and the original source.
#[test]
fn provider_secrets_fail_early_with_context() {
    let path = std::env::temp_dir().join(format!("piquel-provider-secret-{}", TokenId::new()));
    let config = || ProviderConfig {
        client_id: "client".into(),
        client_secret: SecretReference::parse(&format!("file://{}", path.display()))
            .expect("reference"),
    };
    let error = config()
        .resolve(Provider::GitHub)
        .err()
        .expect("missing file rejected");
    assert!(
        error
            .to_string()
            .starts_with(ProviderConfig::variables(Provider::GitHub).1.name())
    );
    assert!(std::error::Error::source(&error).is_some());
    for contents in [b"".as_slice(), &[0xff]] {
        std::fs::write(&path, contents).expect("secret file");
        assert!(config().resolve(Provider::Google).is_err());
    }
    std::fs::write(&path, "secret").expect("secret file");
    let resolved = config().resolve(Provider::Google).expect("valid secret");
    std::fs::remove_file(path).expect("remove secret");
    assert_eq!(resolved.client_secret.expose_secret(), b"secret");
}

/// Cancelled or failed authorization preserves the original continuation and consumes state.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn failed_provider_preserves_stored_continuation_and_consumes_state() {
    let mut test = TestApp::new().await;
    test.app
        .endpoints
        .get_mut(&Provider::GitHub)
        .expect("GitHub facts")
        .token
        .push_str("/missing");
    let router = test.app.clone().routes();
    let destination = "/oauth/authorize/resume?transaction=trusted-transaction";
    for (callback_query, error) in [
        ("error=access_denied", "social_cancelled"),
        ("code=invalid", "social_failed"),
        ("code=", "social_failed"),
        ("", "social_failed"),
    ] {
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::POST,
                "/login/github/start",
                None,
                &serde_json::json!({"return_to":destination}),
            ))
            .await
            .expect("start");
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("pair")
            .to_owned();
        let body = TestApp::json(response).await;
        let authorization = Url::parse(body["redirect_url"].as_str().expect("URL")).expect("URL");
        let state = authorization
            .query_pairs()
            .find(|(key, _)| key == "state")
            .expect("state")
            .1
            .into_owned();
        let path = format!(
            "/login/github/callback?{callback_query}&state={state}&return_to=https://evil.example"
        );
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::GET,
                &path,
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("cancel");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let target = Url::parse(
            response.headers()[header::LOCATION]
                .to_str()
                .expect("location"),
        )
        .expect("target");
        assert_eq!(target.origin(), test.app.origin.as_url().origin());
        assert!(
            target
                .query_pairs()
                .any(|(key, value)| key == "return_to" && value == destination)
        );
        assert!(
            target
                .query_pairs()
                .any(|(key, value)| key == "error" && value == error)
        );
        let response = router
            .clone()
            .oneshot(TestApp::request(
                Method::GET,
                &path,
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("replay");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
