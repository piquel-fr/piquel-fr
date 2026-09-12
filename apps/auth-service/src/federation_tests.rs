use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
    routing::post,
};
use piquel_repository::{DatabaseConfig, InsertPasskey, InsertUser, InsertVerifiedEmail};
use tower::ServiceExt;

struct TestApp {
    app: FederationApplication,
    task: tokio::task::JoinHandle<()>,
    secret_file: std::path::PathBuf,
    subject: String,
}
impl Drop for TestApp {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.secret_file);
    }
}
impl TestApp {
    async fn new() -> Self {
        Self::with_email(None).await
    }
    async fn with_email(email: Option<&str>) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name an isolated migrated PostgreSQL database");
        let database = Database::connect(
            DatabaseConfig::new_development(&url, 5, StdDuration::from_secs(5))
                .expect("database configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let subject = OsRng.next_u64().max(1);
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
        let config = ProviderConfiguration {
            client_id: "test-client".into(),
            client_secret: SecretReference::parse(&format!("file://{}", secret_file.display()))
                .expect("secret reference"),
        };
        let mut app = FederationApplication::new(
            database,
            &Url::parse("https://auth.piquel.fr/").expect("origin"),
            Some(config),
            None,
        )
        .expect("federation");
        app.endpoints.github_token = format!("{base}/token");
        app.endpoints.github_user = format!("{base}/user");
        app.endpoints.github_emails = format!("{base}/emails");
        Self {
            app,
            task,
            secret_file,
            subject: subject.to_string(),
        }
    }
    async fn callback(&self) -> Response {
        let router = routes(self.app.clone());
        let response = router
            .clone()
            .oneshot(request(
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
        let body = json(response).await;
        let url = Url::parse(body["redirect_url"].as_str().expect("redirect")).expect("url");
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .expect("state")
            .1
            .into_owned();
        router
            .oneshot(request(
                Method::GET,
                &format!("/login/github/callback?state={state}&code=mock-code"),
                Some(&cookie),
                &serde_json::Value::Null,
            ))
            .await
            .expect("callback")
    }
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
    async fn pending(
        &self,
        owner: Option<UserId>,
        email: Option<&str>,
    ) -> (PendingFederation, HeaderMap) {
        let secret = BrowserSecret::random();
        let pending = PendingFederation {
            id: TokenId::new(),
            browser_digest: secret.digest(),
            provider: "github".into(),
            issuer: Provider::GitHub.issuer().into(),
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
            HeaderValue::from_str(&format!("{PENDING_COOKIE}={}", secret.0)).expect("cookie"),
        );
        (pending, headers)
    }
    async fn session(&self, user_id: UserId, grant: bool) -> (SessionId, String) {
        let mut tx = self.app.database.begin().await.expect("transaction");
        let cookie = security::create_session(&mut tx, user_id, AuthenticationMethod::Federation)
            .await
            .expect("session");
        let raw = cookie.split(';').next().expect("cookie pair").to_owned();
        tx.commit().await.expect("commit");
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&raw).expect("cookie"));
        let session = security::session(&self.app.database, &headers)
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
}
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
async fn json(response: Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.expect("body"))
        .expect("JSON")
}

#[test]
fn return_destinations_and_browser_bindings_are_strict() {
    for path in [
        "//evil.test",
        "/\\evil.test",
        "https://evil.test",
        "/login#x",
        "/\n/evil",
    ] {
        assert!(validate_return_to(Some(path)).is_err(), "{path}");
    }
    assert_eq!(
        validate_return_to(Some("/oauth/authorize?request=abc")).expect("local return"),
        "/oauth/authorize?request=abc"
    );
    let secret = BrowserSecret::random();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{PENDING_COOKIE}={0}; {PENDING_COOKIE}={0}",
            secret.0
        ))
        .expect("cookie"),
    );
    assert!(BrowserSecret::from_headers(&headers, PENDING_COOKIE).is_err());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn provider_mock_callback_requires_browser_state_and_stays_pending() {
    let test = TestApp::new().await;
    let router = routes(test.app.clone());
    let response = router
        .clone()
        .oneshot(request(
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
    let body = json(response).await;
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
        .oneshot(request(Method::GET, &path, None, &serde_json::Value::Null))
        .await
        .expect("unbound callback");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(request(
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
        .oneshot(request(
            Method::GET,
            &path,
            Some(&cookie),
            &serde_json::Value::Null,
        ))
        .await
        .expect("replay");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn onboarding_commits_only_with_first_key_and_browser_and_never_claims_existing_email() {
    let test = TestApp::new().await;
    let (pending, headers) = test.pending(None, None).await;
    assert!(
        pending_signup(&test.app.database, &headers)
            .await
            .expect("pending signup")
            .is_some()
    );
    let user = test.user(None, false).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        attach_signup(&mut tx, pending.id, &headers, user)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
    let mut tx = test.app.database.begin().await.expect("tx");
    test.key(&mut tx, user).await;
    assert!(
        attach_signup(&mut tx, pending.id, &HeaderMap::new(), user)
            .await
            .is_err()
    );
    attach_signup(&mut tx, pending.id, &headers, user)
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
        attach_signup(&mut tx, pending.id, &headers, user)
            .await
            .is_err()
    );
    tx.rollback().await.expect("rollback");
}

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
    let router = routes(test.app.clone());
    for cookie in [&other_cookie, &target_cookie] {
        let response = router
            .clone()
            .oneshot(request(
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
        .oneshot(request(
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
        .oneshot(request(
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
        .insert_identity(&pending.identity(other))
        .await
        .expect("unlinked subject reusable");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn google_mock_validates_signature_audience_nonce_and_expiry_without_requiring_email() {
    use jsonwebtoken::{EncodingKey, Header, encode};
    let mut test = TestApp::new().await;
    let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA test key");
    let encoding =
        EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().expect("PEM")).expect("JWT key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("google-test".into());
    let mut claims = serde_json::json!({"iss":"https://accounts.google.com","sub":"12345","aud":"test-client","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+300,"nonce":"test-nonce"});
    let valid = encode(&header, &claims, &encoding).expect("signed token");
    claims["aud"] = serde_json::json!("another-client");
    let wrong_audience = encode(&header, &claims, &encoding).expect("signed token");
    claims["aud"] = serde_json::json!("test-client");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() - 120);
    let expired = encode(&header, &claims, &encoding).expect("signed token");
    let other_rsa = openssl::rsa::Rsa::generate(2048).expect("untrusted key");
    let other_encoding =
        EncodingKey::from_rsa_pem(&other_rsa.private_key_to_pem().expect("PEM")).expect("JWT key");
    claims["exp"] = serde_json::json!(Utc::now().timestamp() + 300);
    let wrong_signature =
        encode(&header, &claims, &other_encoding).expect("untrusted signed token");
    let keys = serde_json::json!({"keys":[{"kid":"google-test","kty":"RSA","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),"e":URL_SAFE_NO_PAD.encode(rsa.e().to_vec())}]});
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
    test.app.endpoints.google_keys = format!("{base}/keys");
    let response = test
        .app
        .client
        .get(format!("{base}/token/valid"))
        .send()
        .await
        .expect("valid response");
    let identity = test
        .app
        .google_identity(response, "test-client", "test-nonce")
        .await
        .expect("valid Google identity without email");
    assert_eq!(identity.subject, "12345");
    assert!(identity.email.is_none());
    for (kind, nonce) in [
        ("valid", "wrong-nonce"),
        ("wrong-audience", "test-nonce"),
        ("expired", "test-nonce"),
        ("wrong-signature", "test-nonce"),
    ] {
        let response = test
            .app
            .client
            .get(format!("{base}/token/{kind}"))
            .send()
            .await
            .expect("mock response");
        assert!(
            test.app
                .google_identity(response, "test-client", nonce)
                .await
                .is_err(),
            "{kind} {nonce}"
        );
    }
    task.abort();
}

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
            .find_active(Provider::GitHub.issuer(), &test.subject)
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
            provider: "github".into(),
            issuer: Provider::GitHub.issuer().into(),
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
    let session = security::session(&test.app.database, &headers)
        .await
        .expect("social session");
    assert_eq!(
        session.user_id, subject_owner,
        "stable subject takes priority over email observation"
    );
    assert!(
        security::management(&test.app.database, &headers)
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
