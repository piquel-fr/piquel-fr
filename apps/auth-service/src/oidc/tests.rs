use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
};
use piquel_auth_protocol::AuthenticationMethod;
use piquel_repository::{BootstrapOidcClient, DatabaseConfig, InsertUser, InsertVerifiedEmail};
use tower::ServiceExt;

struct Flow {
    app: OidcApplication,
    client: BootstrapOidcClient,
    cookie: String,
    user_id: UserId,
    basic: Option<String>,
}
impl Flow {
    async fn new(confidential: bool, trusted: bool) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must name a disposable PostgreSQL database");
        let db = Database::connect(
            DatabaseConfig::new_development(&url, 5, std::time::Duration::from_secs(5))
                .expect("valid local test database configuration"),
        )
        .await
        .expect("connect to the disposable PostgreSQL database");
        db.run_migrations()
            .await
            .expect("apply test database migrations");
        let user_id = UserId::new();
        let mut tx = db.begin().await.expect("begin test account transaction");
        tx.users()
            .insert(&InsertUser {
                id: user_id,
                username: format!("oidc_{}", &user_id.to_string()[24..]),
                display_name: "OIDC Test".into(),
            })
            .await
            .expect("insert test account");
        tx.emails()
            .insert_verified(&InsertVerifiedEmail {
                id: TokenId::new(),
                user_id,
                normalized_email: format!("{user_id}@example.com"),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await
            .expect("insert verified test email");
        let cookie =
            crate::security::create_session(&mut tx, user_id, AuthenticationMethod::Passkey)
                .await
                .expect("create test browser session")
                .split(';')
                .next()
                .expect("extract session cookie pair")
                .to_owned();
        tx.commit().await.expect("commit test account transaction");
        let secret = "randomly-generated-example-secret-for-testing-0123456789";
        let client = BootstrapOidcClient {
            id: format!("test-{user_id}"),
            display_name: "Test app".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_uris: vec!["https://client.example/logout".into()],
            allowed_scopes: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ],
            allowed_audiences: vec!["test-api".into()],
            allow_refresh: true,
            enabled: true,
            trusted,
            client_secret_hash: confidential.then(|| {
                OidcApplication::client_secret_hash(secret).expect("hash test client secret")
            }),
        };
        db.oidc()
            .bootstrap_client(&client)
            .await
            .expect("register test OIDC client");
        let basic = confidential.then(|| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{secret}", client.id))
            )
        });
        let app = OidcApplication::new(
            db,
            &Url::parse("https://auth.example.com").expect("parse test issuer URL"),
            &[7; 32],
            Arc::new(
                Rs256KeyProvider::generate_for_development("oidc-tests")
                    .expect("generate test RSA signing key"),
            ),
        )
        .expect("construct test OIDC application");
        Self {
            app,
            client,
            cookie,
            user_id,
            basic,
        }
    }
    async fn request(
        &self,
        method: Method,
        uri: &str,
        form: &[(&str, &str)],
        basic: Option<&str>,
    ) -> Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, &self.cookie)
            .header(header::ORIGIN, "https://auth.example.com")
            .header("x-piquel-csrf", "1");
        if let Some(basic) = basic {
            builder = builder.header(header::AUTHORIZATION, basic);
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().copied())
            .finish();
        let request = builder
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("build test HTTP request");
        routes(self.app.clone())
            .oneshot(request)
            .await
            .expect("dispatch OIDC HTTP request")
    }
    async fn authorize(&self, scope: &str, prompt: Option<&str>) -> Response {
        self.authorize_with(Method::GET, scope, prompt, &[]).await
    }
    async fn authorize_with(
        &self,
        method: Method,
        scope: &str,
        prompt: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Response {
        let mut url = Url::parse("https://auth.example.com/oauth/authorize")
            .expect("parse authorization endpoint URL");
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &self.client.id),
            ("redirect_uri", &self.client.redirect_uris[0]),
            ("scope", scope),
            ("state", "test-state"),
            ("nonce", "test-nonce"),
            ("code_challenge_method", "S256"),
            (
                "code_challenge",
                &URL_SAFE_NO_PAD.encode(Sha256::digest(Self::verifier().as_bytes())),
            ),
        ]);
        if let Some(prompt) = prompt {
            url.query_pairs_mut().append_pair("prompt", prompt);
        }
        url.query_pairs_mut().extend_pairs(extra.iter().copied());
        if method == Method::POST {
            let owned: Vec<_> = url.query_pairs().into_owned().collect();
            let fields: Vec<_> = owned
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            self.request(method, url.path(), &fields, None).await
        } else {
            self.request(
                method,
                &format!(
                    "{}?{}",
                    url.path(),
                    url.query().expect("authorization query")
                ),
                &[],
                None,
            )
            .await
        }
    }
    fn verifier() -> &'static str {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    }
    fn location(response: &Response) -> Url {
        Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .expect("authorization response has a Location header")
                .to_str()
                .expect("Location header is valid text"),
        )
        .expect("Location header contains an absolute URL")
    }
    fn parameter(url: &Url, name: &str) -> String {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .expect("redirect contains expected query parameter")
            .1
            .into_owned()
    }
    async fn json(response: Response) -> Value {
        serde_json::from_slice(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("read complete HTTP response body"),
        )
        .expect("decode HTTP JSON response")
    }
    async fn code(&self, scopes: &str) -> String {
        let response = self.authorize(scopes, None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let mut location = Self::location(&response);
        if location.path() == "/authorize" {
            let transaction = Self::parameter(&location, "transaction");
            let response = self
                .request(
                    Method::POST,
                    "/oauth/authorize/decision",
                    &[("transaction", &transaction), ("decision", "approve")],
                    None,
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            location = Url::parse(
                Self::json(response).await["redirect_url"]
                    .as_str()
                    .expect("decision response includes redirect_url"),
            )
            .expect("decision redirect is a valid URL");
        }
        Self::parameter(&location, "code")
    }
    async fn exchange(&self, code: &str, verifier: &str, basic: Option<&str>) -> Response {
        self.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &self.client.id),
                ("redirect_uri", &self.client.redirect_uris[0]),
                ("code", code),
                ("code_verifier", verifier),
            ],
            basic,
        )
        .await
    }
    async fn refresh(&self, token: &str) -> Response {
        self.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &self.client.id),
                ("refresh_token", token),
            ],
            self.basic.as_deref(),
        )
        .await
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn public_consent_pkce_claim_scoping_and_replay() {
    let flow = Flow::new(false, false).await;
    let response = flow.authorize("openid", Some("none")).await;
    assert_eq!(
        Flow::parameter(&Flow::location(&response), "error"),
        "consent_required"
    );
    let code = flow.code("openid").await;
    assert_eq!(
        flow.exchange(&code, "wrong", None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow.exchange(&code, Flow::verifier(), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let claims = flow
        .app
        .keys
        .verify(
            tokens["id_token"]
                .as_str()
                .expect("token response contains an ID token"),
            "JWT",
            &flow.app.issuer,
        )
        .expect("verify scoped ID token");
    assert_eq!(claims["nonce"], "test-nonce");
    assert!(claims.get("name").is_none());
    assert!(claims.get("email").is_none());
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow.authorize("openid", Some("none")).await;
    assert!(
        Flow::location(&response)
            .query_pairs()
            .any(|(name, _)| name == "code")
    );
    let response = flow.authorize("openid email", Some("none")).await;
    assert_eq!(
        Flow::parameter(&Flow::location(&response), "error"),
        "consent_required"
    );
    let response = flow.authorize("openid", Some("login")).await;
    assert_eq!(Flow::location(&response).path(), "/login");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "The scenario follows one refresh family through narrowing, replay and logout."
)]
async fn confidential_refresh_rotation_logout_and_client_binding() {
    let flow = Flow::new(true, true).await;
    let code = flow.code("openid email offline_access").await;
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let claims = flow
        .app
        .keys
        .verify(
            tokens["id_token"]
                .as_str()
                .expect("token response contains an ID token"),
            "JWT",
            &flow.app.issuer,
        )
        .expect("verify confidential client ID token");
    assert_eq!(claims["email"], format!("{}@example.com", flow.user_id));
    assert_eq!(claims["email_verified"], true);
    let old = tokens["refresh_token"]
        .as_str()
        .expect("token response contains a refresh token");
    let other = Flow::new(false, true).await;
    assert_eq!(other.refresh(old).await.status(), StatusCode::BAD_REQUEST);
    let invalid = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &flow.client.id),
                ("refresh_token", old),
                ("scope", "openid admin"),
            ],
            flow.basic.as_deref(),
        )
        .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(Flow::json(invalid).await["error"], "invalid_scope");
    let response = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &flow.client.id),
                ("refresh_token", old),
                ("scope", "openid"),
            ],
            flow.basic.as_deref(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed = Flow::json(response).await;
    assert_eq!(narrowed["scope"], "openid");
    let narrowed_claims = flow
        .app
        .keys
        .verify(
            narrowed["id_token"]
                .as_str()
                .expect("refresh response contains an ID token"),
            "JWT",
            &flow.app.issuer,
        )
        .expect("verify narrowed ID token");
    assert!(narrowed_claims.get("email").is_none());
    let fresh = narrowed["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    assert_eq!(flow.refresh(old).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(flow.refresh(&fresh).await.status(), StatusCode::BAD_REQUEST);
    let code = flow.code("openid offline_access").await;
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    let tokens = Flow::json(response).await;
    let response = flow
        .request(
            Method::POST,
            "/oidc/logout",
            &[
                ("client_id", &flow.client.id),
                ("post_logout_redirect_uri", &flow.client.post_logout_uris[0]),
            ],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("Set-Cookie header is valid text")
            .contains("Max-Age=0")
    );
    assert_eq!(
        flow.refresh(
            tokens["refresh_token"]
                .as_str()
                .expect("token response contains a refresh token")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        Flow::parameter(
            &Flow::location(&flow.authorize("openid", Some("none")).await),
            "error"
        ),
        "login_required"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn policy_reduction_blocks_outstanding_codes_and_refresh() {
    let mut flow = Flow::new(false, true).await;
    let code = flow.code("openid email").await;
    flow.client.allowed_scopes = vec!["openid".into(), "offline_access".into()];
    flow.app
        .database
        .oidc()
        .bootstrap_client(&flow.client)
        .await
        .expect("apply reduced client scope policy");
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let code = flow.code("openid offline_access").await;
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    flow.client.allow_refresh = false;
    flow.app
        .database
        .oidc()
        .bootstrap_client(&flow.client)
        .await
        .expect("disable client refresh permission");
    assert_eq!(
        flow.refresh(
            tokens["refresh_token"]
                .as_str()
                .expect("token response contains a refresh token")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .request(
            Method::GET,
            "/oidc/logout?client_id=unknown&post_logout_redirect_uri=https%3A%2F%2Fevil.example",
            &[],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authorization_hints_bind_initial_resumed_and_consent_requests() {
    let flow = Flow::new(false, true).await;
    let now = Utc::now().timestamp();
    let claims = json!({"iss":flow.app.issuer,"sub":flow.user_id,"aud":flow.client.id,"iat":now-600,"exp":now-300});
    let hint = flow
        .app
        .keys
        .sign("JWT", &claims)
        .expect("sign expired hint");
    let response = flow
        .authorize_with(
            Method::GET,
            "openid",
            Some("none"),
            &[("id_token_hint", &hint)],
        )
        .await;
    assert!(!Flow::parameter(&Flow::location(&response), "code").is_empty());
    for (field, value) in [
        ("iss", json!("https://foreign.example")),
        ("aud", json!("other-client")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        let hint = flow
            .app
            .keys
            .sign("JWT", &invalid)
            .expect("sign invalid hint");
        let response = flow
            .authorize_with(
                Method::GET,
                "openid",
                Some("none"),
                &[("id_token_hint", &hint)],
            )
            .await;
        assert_eq!(
            Flow::parameter(&Flow::location(&response), "error"),
            "invalid_request"
        );
    }
    let mut other = claims;
    other["sub"] = json!(UserId::new());
    let hint = flow
        .app
        .keys
        .sign("JWT", &other)
        .expect("sign other account hint");
    let response = flow
        .authorize_with(
            Method::GET,
            "openid",
            Some("none"),
            &[("id_token_hint", &hint)],
        )
        .await;
    assert_eq!(
        Flow::parameter(&Flow::location(&response), "error"),
        "login_required"
    );
    let response = flow
        .authorize_with(Method::GET, "openid", None, &[("id_token_hint", &hint)])
        .await;
    let location = Flow::location(&response);
    assert_eq!(location.path(), "/login");
    let transaction = Flow::parameter(&location, "transaction");
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    assert_eq!(Flow::location(&response).path(), "/login");
    let response = flow
        .request(
            Method::POST,
            "/oauth/authorize/decision",
            &[("transaction", &transaction), ("decision", "approve")],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn post_protocol_endpoints_and_error_contracts() {
    let flow = Flow::new(false, true).await;
    for (name, value, expected) in [
        ("id_token_hint", "invalid", "invalid_request"),
        ("request", "ignored.jwt", "request_not_supported"),
        (
            "request_uri",
            "https://example.com/request.jwt",
            "request_uri_not_supported",
        ),
        ("response_mode", "form_post", "invalid_request"),
    ] {
        let response = flow
            .authorize_with(Method::GET, "openid", Some("none"), &[(name, value)])
            .await;
        assert_eq!(
            Flow::parameter(&Flow::location(&response), "error"),
            expected
        );
    }
    let discovery = Flow::json(
        flow.request(Method::GET, "/.well-known/openid-configuration", &[], None)
            .await,
    )
    .await;
    assert_eq!(discovery["request_parameter_supported"], false);
    assert_eq!(discovery["request_uri_parameter_supported"], false);
    let response = flow
        .authorize_with(Method::POST, "openid profile", None, &[])
        .await;
    let code = Flow::parameter(&Flow::location(&response), "code");
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    let bearer = format!(
        "Bearer {}",
        tokens["access_token"].as_str().expect("access token")
    );
    let response = flow
        .request(Method::POST, "/oidc/userinfo", &[], Some(&bearer))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let userinfo = Flow::json(response).await;
    assert_eq!(userinfo["sub"], json!(flow.user_id));
    assert!(userinfo["profile_version"].is_number());
    let response = flow
        .request(Method::POST, "/oidc/userinfo", &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer error=\"invalid_token\""
    );
    let response = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[("client_id", &flow.client.id)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(Flow::json(response).await["error"], "invalid_request");
}
