//! Focused parsing checks and database-backed OAuth/OIDC scenarios.

use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use piquel_auth_protocol::{AuthenticationMethod, UserId, claims::IdTokenClaims};
use piquel_crypto::Secret;
use piquel_repository::{BootstrapOidcClient, DatabaseConfig, InsertUser, InsertVerifiedEmail};
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;

/// Secret of confidential scenario clients.
const CLIENT_SECRET: &str = "randomly-generated-example-secret-for-testing-0123456789";

/// Database-backed OIDC scenario with a provisioned client and authenticated browser.
struct Flow {
    /// Application under test, sharing the scenario database.
    app: OidcApplication,
    /// Client identifier bound into the token claims.
    client: BootstrapOidcClient,
    /// Authenticated browser cookie pair sent by the scenario.
    cookie: String,
    /// Scenario account whose claims and grants are checked.
    user_id: UserId,
    /// Optional encoded credentials for a confidential scenario client.
    basic: Option<String>,
}
impl Flow {
    /// Creates a disposable account, client registration and persistent-key OIDC application.
    async fn new(confidential: bool, trusted: bool) -> Self {
        Self::at(
            "https://auth.example.com",
            "test-api",
            confidential,
            trusted,
        )
        .await
    }

    /// Like [`Self::new`], for an issuer at `origin` whose client may request tokens
    /// for `audience`.
    async fn at(origin: &str, audience: &str, confidential: bool, trusted: bool) -> Self {
        let url = piquel_common::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("TEST_DATABASE_URL must name a disposable PostgreSQL database");
        let db = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5))
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
            crate::security::Session::create(&mut tx, user_id, AuthenticationMethod::Passkey)
                .await
                .expect("create test browser session");
        let cookie = format!(
            "{}={}",
            crate::security::BrowserCookie::Session.as_str(),
            cookie.encoded()
        );
        tx.commit().await.expect("commit test account transaction");
        let client = BootstrapOidcClient {
            id: format!("test-{user_id}"),
            display_name: "Test app".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_uris: vec!["https://client.example/logout".into()],
            allowed_scopes: vec![
                Scope::OpenId.as_str().into(),
                Scope::Profile.as_str().into(),
                Scope::Email.as_str().into(),
                Scope::OfflineAccess.as_str().into(),
            ],
            allowed_audiences: vec![audience.into()],
            allow_refresh: true,
            enabled: true,
            trusted,
            client_secret_hash: confidential.then(|| {
                Digest::client_secret(CLIENT_SECRET)
                    .expect("hash test client secret")
                    .as_bytes()
                    .to_vec()
            }),
        };
        db.oidc()
            .bootstrap_client(&client)
            .await
            .expect("register test OIDC client");
        let basic = confidential.then(|| {
            format!(
                "{} {}",
                AuthScheme::Basic.as_str(),
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{CLIENT_SECRET}", client.id))
            )
        });
        let app = OidcApplication::new(
            db,
            &OidcConfig {
                origin: origin.parse::<piquel_common::Origin>().expect("issuer"),
                keys: Arc::new(Rs256Key::generate("oidc-tests").expect("RSA signing key")),
                refresh_key: Arc::new(Secret::derive(&[7; 32], REFRESH_KEY_LABEL).expect("HMAC")),
                clients: vec![],
                public_redirects: vec![],
            },
        )
        .expect("OIDC application");
        Self {
            app,
            client,
            cookie,
            user_id,
            basic,
        }
    }
    /// Dispatches an encoded protocol request through the OIDC routes.
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
            .header(header::ORIGIN, &self.app.issuer)
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
        self.app
            .clone()
            .routes()
            .oneshot(request)
            .await
            .expect("dispatch OIDC HTTP request")
    }
    /// Accepts query authorization requests and returns OAuth errors for malformed input.
    async fn authorize(&self, scope: &str, prompt: Option<&str>) -> Response {
        self.authorize_with(Method::GET, scope, prompt, &[]).await
    }
    /// Builds an authorization request with optional hint or security parameter overrides.
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
            ("response_type", ResponseType::Code.as_str()),
            ("client_id", &self.client.id),
            ("redirect_uri", &self.client.redirect_uris[0]),
            ("scope", scope),
            ("state", "test-state"),
            ("nonce", "test-nonce"),
            ("code_challenge_method", CodeChallengeMethod::S256.as_str()),
            (
                "code_challenge",
                &piquel_crypto::Pkce::challenge(Self::verifier()).expect("PKCE"),
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
    /// Returns the valid PKCE verifier used by database-backed scenarios.
    fn verifier() -> &'static str {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    }
    /// Reads the absolute destination of a protocol redirect response.
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
    /// Reads a redirect back to the client, which must name this issuer in `iss` (RFC 9207).
    fn client_redirect(&self, response: &Response) -> Url {
        self.issued(Self::location(response))
    }
    /// Returns an authorization response URL after checking its `iss`.
    fn issued(&self, url: Url) -> Url {
        assert_eq!(Self::parameter(&url, "iss"), self.app.issuer);
        url
    }
    /// Extracts a required query parameter from a protocol redirect.
    fn parameter(url: &Url, name: &str) -> String {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .expect("redirect contains expected query parameter")
            .1
            .into_owned()
    }
    /// Reads and decodes the scenario’s JSON response.
    async fn json(response: Response) -> Value {
        serde_json::from_slice(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("read complete HTTP response body"),
        )
        .expect("decode HTTP JSON response")
    }
    /// Completes explicit consent when needed and extracts the issued authorization code.
    async fn code(&self, scopes: &str) -> String {
        let response = self.authorize(scopes, None).await;
        Self::parameter(&self.consent(response).await, "code")
    }
    /// Follows an authorization response through consent, when needed, to the client
    /// redirect, whose `iss` it checks.
    async fn consent(&self, response: Response) -> Url {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let mut location = Self::location(&response);
        if location.path() == "/authorize" {
            let transaction = Self::parameter(&location, "transaction");
            let response = self
                .request(
                    Method::POST,
                    "/oauth/authorize/decision",
                    &[("transaction", &transaction), ("decision", APPROVE_CONSENT)],
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
        self.issued(location)
    }
    /// Exchanges a scenario code with the requested verifier and client credentials.
    async fn exchange(&self, code: &str, verifier: &str, basic: Option<&str>) -> Response {
        self.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::AuthorizationCode.as_str()),
                ("client_id", &self.client.id),
                ("redirect_uri", &self.client.redirect_uris[0]),
                ("code", code),
                ("code_verifier", verifier),
            ],
            basic,
        )
        .await
    }
    /// Rotates a scenario refresh token using its registered client credentials.
    async fn refresh(&self, token: &str) -> Response {
        self.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("client_id", &self.client.id),
                ("refresh_token", token),
            ],
            self.basic.as_deref(),
        )
        .await
    }
}

/// Both well-known paths serve the same cacheable, typed document, and every endpoint
/// it advertises is routed on the issuer.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn metadata_is_one_document_whose_endpoints_are_routed() {
    let flow = Flow::new(false, false).await;
    let mut documents = vec![];
    for path in [routes::oidc::DISCOVERY, routes::oidc::OAUTH_METADATA] {
        let response = flow.request(Method::GET, path, &[], None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            PublicDocument::CACHE_CONTROL
        );
        documents.push(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("read metadata"),
        );
    }
    assert_eq!(documents[0], documents[1]);
    let metadata: ServerMetadata = serde_json::from_slice(&documents[0]).expect("typed metadata");
    assert_eq!(metadata.issuer, flow.app.issuer);
    let Value::Object(fields) = serde_json::from_slice(&documents[0]).expect("metadata JSON")
    else {
        panic!("metadata is not a JSON object");
    };
    for (name, value) in fields {
        if !(name.ends_with("_endpoint") || name == "jwks_uri") {
            continue;
        }
        let url = Url::parse(value.as_str().expect("endpoint text")).expect("endpoint URL");
        assert_eq!(
            url.origin().ascii_serialization(),
            metadata.issuer,
            "{name}"
        );
        let response = flow.request(Method::GET, url.path(), &[], None).await;
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "{name}");
    }
}

/// Checks public-client consent, PKCE, scoped claims and one-use authorization codes.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn public_consent_pkce_claim_scoping_and_replay() {
    let flow = Flow::new(false, false).await;
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        Flow::parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::ConsentRequired.as_str()
    );
    let code = flow.code(Scope::OpenId.as_str()).await;
    assert_eq!(
        flow.exchange(&code, "wrong", None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow.exchange(&code, Flow::verifier(), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let claims: IdTokenClaims = flow
        .app
        .keys
        .verify(
            tokens["id_token"]
                .as_str()
                .expect("token response contains an ID token"),
            TokenType::Id,
            &flow.app.issuer,
        )
        .expect("verify scoped ID token");
    assert_eq!(claims.nonce.as_deref(), Some("test-nonce"));
    assert!(claims.profile.name.is_none());
    assert!(claims.profile.email.is_none());
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
        .await;
    assert!(
        flow.client_redirect(&response)
            .query_pairs()
            .any(|(name, _)| name == "code")
    );
    let response = flow
        .authorize(EMAIL_SCOPES, Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        Flow::parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::ConsentRequired.as_str()
    );
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::Login.as_str()))
        .await;
    assert_eq!(Flow::location(&response).path(), "/login");
}

/// Checks refresh narrowing, replay revocation, client binding and logout.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "The scenario follows one refresh family through narrowing, replay and logout."
)]
async fn confidential_refresh_rotation_logout_and_client_binding() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(EMAIL_REFRESH_SCOPES).await;
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let claims: IdTokenClaims = flow
        .app
        .keys
        .verify(
            tokens["id_token"]
                .as_str()
                .expect("token response contains an ID token"),
            TokenType::Id,
            &flow.app.issuer,
        )
        .expect("verify confidential client ID token");
    assert_eq!(
        claims.profile.email,
        Some(format!("{}@example.com", flow.user_id))
    );
    assert_eq!(claims.profile.email_verified, Some(true));
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
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("client_id", &flow.client.id),
                ("refresh_token", old),
                ("scope", UNGRANTED_SCOPES),
            ],
            flow.basic.as_deref(),
        )
        .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(invalid).await["error"],
        OAuthCode::InvalidScope.as_str()
    );
    let response = flow
        .request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("client_id", &flow.client.id),
                ("refresh_token", old),
                ("scope", Scope::OpenId.as_str()),
            ],
            flow.basic.as_deref(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let narrowed = Flow::json(response).await;
    assert_eq!(narrowed["scope"], Scope::OpenId.as_str());
    let narrowed_claims: IdTokenClaims = flow
        .app
        .keys
        .verify(
            narrowed["id_token"]
                .as_str()
                .expect("refresh response contains an ID token"),
            TokenType::Id,
            &flow.app.issuer,
        )
        .expect("verify narrowed ID token");
    assert!(narrowed_claims.profile.email.is_none());
    let fresh = narrowed["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    assert_eq!(flow.refresh(old).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(flow.refresh(&fresh).await.status(), StatusCode::BAD_REQUEST);
    let code = flow.code(REFRESH_SCOPES).await;
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
            &flow.client_redirect(
                &flow
                    .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
                    .await
            ),
            "error"
        ),
        OAuthCode::LoginRequired.as_str()
    );
}

/// Replaying a redeemed code revokes the refresh family it produced, while the same
/// code ID with a guessed secret revokes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn code_replay_revokes_its_refresh_family() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = Flow::json(response).await;
    let guessed = OpaqueToken {
        id: OpaqueToken::parse(TokenPrefix::AuthorizationCode, &code)
            .expect("issued code parses")
            .id,
        ..OpaqueToken::new(TokenPrefix::AuthorizationCode).expect("random secret")
    }
    .encoded();
    assert_eq!(
        flow.exchange(&guessed, Flow::verifier(), flow.basic.as_deref())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = flow
        .refresh(
            tokens["refresh_token"]
                .as_str()
                .expect("token response contains a refresh token"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK, "a guess revokes nothing");
    let rotated = Flow::json(response).await["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    let replay = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(replay).await["error"],
        OAuthCode::InvalidGrant.as_str()
    );
    assert_eq!(
        flow.refresh(&rotated).await.status(),
        StatusCode::BAD_REQUEST
    );
}

/// Checks that policy reductions reject new requests and invalidate outstanding grants,
/// and that unsafe logout redirects are refused.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn policy_reduction_blocks_outstanding_codes_and_refresh() {
    let mut flow = Flow::new(false, true).await;
    let code = flow.code(EMAIL_SCOPES).await;
    flow.client.allowed_scopes = vec![
        Scope::OpenId.as_str().into(),
        Scope::OfflineAccess.as_str().into(),
    ];
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
    assert_eq!(
        Flow::parameter(
            &flow.client_redirect(&flow.authorize(EMAIL_SCOPES, None).await),
            "error"
        ),
        OAuthCode::InvalidScope.as_str()
    );
    let code = flow.code(REFRESH_SCOPES).await;
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

/// Checks that ID hints bind the account across initial, resumed and consent requests.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authorization_hints_bind_initial_resumed_and_consent_requests() {
    let flow = Flow::new(false, true).await;
    let now = Utc::now().timestamp();
    let claims = json!({"iss":flow.app.issuer,"sub":flow.user_id,"aud":flow.client.id,"iat":now-600,"exp":now-300});
    let hint = flow
        .app
        .keys
        .sign(TokenType::Id, &claims)
        .expect("sign expired hint");
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            Some(Prompt::None.as_str()),
            &[("id_token_hint", &hint)],
        )
        .await;
    assert_ne!(
        Flow::parameter(&flow.client_redirect(&response), "code"),
        ""
    );
    for (field, value) in [
        ("iss", json!("https://foreign.example")),
        ("aud", json!("other-client")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        let hint = flow
            .app
            .keys
            .sign(TokenType::Id, &invalid)
            .expect("sign invalid hint");
        let response = flow
            .authorize_with(
                Method::GET,
                Scope::OpenId.as_str(),
                Some(Prompt::None.as_str()),
                &[("id_token_hint", &hint)],
            )
            .await;
        assert_eq!(
            Flow::parameter(&flow.client_redirect(&response), "error"),
            OAuthCode::InvalidRequest.as_str()
        );
    }
    let mut other = claims;
    other["sub"] = json!(UserId::new());
    let hint = flow
        .app
        .keys
        .sign(TokenType::Id, &other)
        .expect("sign other account hint");
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            Some(Prompt::None.as_str()),
            &[("id_token_hint", &hint)],
        )
        .await;
    assert_eq!(
        Flow::parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::LoginRequired.as_str()
    );
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            None,
            &[("id_token_hint", &hint)],
        )
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
            &[("transaction", &transaction), ("decision", APPROVE_CONSENT)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Checks protocol POST parity and existing OAuth error and challenge formats.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn post_protocol_endpoints_and_error_contracts() {
    let flow = Flow::new(false, true).await;
    for (name, value, expected) in [
        (
            "id_token_hint",
            "invalid",
            OAuthCode::InvalidRequest.as_str(),
        ),
        (
            "request",
            "ignored.jwt",
            OAuthCode::RequestNotSupported.as_str(),
        ),
        (
            "request_uri",
            "https://example.com/request.jwt",
            OAuthCode::RequestUriNotSupported.as_str(),
        ),
        (
            "response_mode",
            "form_post",
            OAuthCode::InvalidRequest.as_str(),
        ),
    ] {
        let response = flow
            .authorize_with(
                Method::GET,
                Scope::OpenId.as_str(),
                Some(Prompt::None.as_str()),
                &[(name, value)],
            )
            .await;
        assert_eq!(
            Flow::parameter(&flow.client_redirect(&response), "error"),
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
    assert_eq!(
        discovery["authorization_response_iss_parameter_supported"],
        true
    );
    let response = flow
        .authorize_with(Method::POST, PROFILE_SCOPES, None, &[])
        .await;
    let code = Flow::parameter(&flow.client_redirect(&response), "code");
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    let bearer = format!(
        "{} {}",
        AuthScheme::Bearer.as_str(),
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
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidRequest.as_str()
    );
}

/// Checks redirect equality, PKCE rejection and opaque-token bounds.
#[test]
fn exact_redirect_and_pkce_and_refresh_bounds() {
    let registered = ["https://a.example/cb".to_owned()];
    assert!(!registered.contains(&"https://a.example/cb.evil".to_owned()));
    assert!(piquel_crypto::Pkce::verify("short", "x").is_err());
    let huge = format!(
        "{}_{}.{:0200}",
        TokenPrefix::RefreshToken,
        TokenId::new(),
        "x"
    );
    assert!(OpaqueToken::parse(TokenPrefix::RefreshToken, &huge).is_err());
}

/// Checks case-insensitive scheme matching without changing credential bytes.
#[test]
fn authentication_schemes_are_case_insensitive() {
    assert_eq!(AuthScheme::Bearer.credentials("bEaReR a.B"), Some("a.B"));
    assert_eq!(AuthScheme::Basic.credentials("BASIC Zm9v"), Some("Zm9v"));
    assert_eq!(AuthScheme::Basic.credentials("Bearer Zm9v"), None);
    assert_eq!(AuthScheme::Bearer.credentials("Bearer"), None);
}

/// HMAC label fixture; matching production key derivation in config.
const REFRESH_KEY_LABEL: &[u8] = b"piquel-refresh-token-digest-v1";
/// Existing scope strings exercise the HTTP wire contract independently of enum serialization.
const EMAIL_REFRESH_SCOPES: &str = "openid email offline_access";
/// Identity and session-bounded refresh requested together.
const REFRESH_SCOPES: &str = "openid offline_access";
/// Public-profile scope fixture.
const PROFILE_SCOPES: &str = "openid profile";
/// Verified-email scope fixture.
const EMAIL_SCOPES: &str = "openid email";
/// Unregistered extension scope fixture used to check rejection.
const UNGRANTED_SCOPES: &str = "openid admin";

/// Checks deduplication, lexical ordering and preservation of registered extension scopes.
#[test]
fn scope_sets_preserve_existing_wire_semantics() {
    let scopes = Scopes::parse("profile openid profile custom.read email").expect("scope set");
    assert!(scopes.contains(Scope::OpenId));
    assert_eq!(
        scopes.wire().to_string(),
        "custom.read email openid profile"
    );
    let stored = scopes.clone().into_stored();
    assert!(scopes.allowed_by(&stored));
    assert!(!scopes.allowed_by(&[Scope::OpenId.as_str().into()]));
    assert_eq!(Scopes::from_stored(&stored), scopes);
    assert!(Scopes::parse(" ").is_err());
    let too_many = (0..=MAX_SCOPES)
        .map(|index| format!("scope{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(Scopes::parse(&too_many).is_err());
}

/// Checks purpose binding and exact opaque envelope/secret round trips.
#[test]
fn opaque_tokens_preserve_envelopes_and_reject_wrong_purpose() {
    for prefix in TokenPrefix::ALL {
        let original = OpaqueToken::new(prefix).expect("random token");
        let encoded = original.encoded();
        let parsed = OpaqueToken::parse(prefix, &encoded).expect("parse envelope");
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.secret.as_bytes(), original.secret.as_bytes());
        assert_eq!(parsed.encoded(), encoded);
        for other in TokenPrefix::ALL {
            if prefix != other {
                assert!(OpaqueToken::parse(other, &encoded).is_err());
            }
        }
    }
}

/// Checks that protocol failures retain both internal and rejected-input source chains.
#[tokio::test]
async fn oauth_failures_preserve_sources_and_statuses() {
    use axum::response::IntoResponse;
    use std::error::Error;
    let error = OAuthError::from(piquel_repository::DatabaseError::Operation(Box::new(
        std::io::Error::other("internal diagnostic"),
    )));
    assert_eq!(
        error.source().expect("internal source").to_string(),
        "internal diagnostic"
    );
    assert_eq!(
        error.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let error = OAuthCode::InvalidGrant.reject_with(
        "code is \"malformed\" \u{2014} retry",
        piquel_crypto::CryptoError::SecretLength,
    );
    assert!(error.source().is_some());
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // The description reaches the client, restricted to the RFC 6749 character set.
    assert_eq!(
        Flow::json(response).await,
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "code is 'malformed' ? retry",
        })
    );
}

/// Existing approve form spelling, independent of the JSON-only consent enum.
const APPROVE_CONSENT: &str = "approve";

/// HTTPS on a local port with a self-signed `localhost` certificate, so the SDK can
/// reach the provider at an `https` issuer as it would in production.
struct TlsListener {
    /// Accepts TCP connections.
    tcp: tokio::net::TcpListener,
    /// Completes each TLS handshake.
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    /// Serves `router` on `tcp` in the background and returns the certificate to trust.
    fn serve(tcp: tokio::net::TcpListener, router: Router) -> reqwest::Certificate {
        use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        )
        .expect("TLS configuration");
        let listener = Self {
            tcp,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        };
        tokio::spawn(async move { axum::serve(listener, router).await });
        reqwest::Certificate::from_der(certified.cert.der()).expect("trusted certificate")
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    /// Retries until a connection completes its handshake.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, address)) = self.tcp.accept().await else {
                continue;
            };
            if let Ok(stream) = self.acceptor.accept(stream).await {
                return (stream, address);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// The resource the SDK scenario's client requests tokens for.
const SDK_RESOURCE: &str = "notes-api";

/// The Rust SDK signs in, validates, refreshes, revokes and logs out against the real
/// provider over HTTPS, and rejects a mixed-up callback before any code exchange.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "The scenario follows one login from authorization through logout."
)]
async fn sdk_login_client_runs_against_the_provider() {
    use piquel_auth::{
        AuthorizeRequest, CallbackParams, ClientConfig, ClientId, Credentials, LoginError,
        OAuthError, Resource, Scopes, Subject,
    };
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider");
    let port = tcp.local_addr().expect("provider address").port();
    let origin = format!("https://localhost:{port}");
    let flow = Flow::at(&origin, SDK_RESOURCE, true, false).await;
    let certificate = TlsListener::serve(tcp, flow.app.clone().routes());
    let http = reqwest::Client::builder()
        .add_root_certificate(certificate)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client");
    let issuer = piquel_auth::Issuer::builder()
        .http_client(http)
        .discover(&origin)
        .await
        .expect("discover the provider");
    let client = issuer.client(ClientConfig {
        client_id: ClientId::new(flow.client.id.clone()),
        credentials: Credentials::Secret(CLIENT_SECRET.into()),
        redirect_uri: flow.client.redirect_uris[0].parse().expect("callback"),
    });
    let (url, pending) = client
        .authorize(&AuthorizeRequest {
            scopes: "profile email offline_access".parse().expect("scopes"),
            ..AuthorizeRequest::default()
        })
        .expect("authorization URL");

    let mixed_up = CallbackParams {
        code: Some("pac_v1_unused".into()),
        state: Some(pending.state().into()),
        iss: Some("https://evil.example".into()),
        ..CallbackParams::default()
    };
    assert!(matches!(
        client.complete(pending.clone(), &mixed_up).await,
        Err(LoginError::IssuerMismatch { .. })
    ));

    let browser = flow
        .request(
            Method::GET,
            &format!("{}?{}", url.path(), url.query().expect("query")),
            &[],
            None,
        )
        .await;
    let callback = flow.consent(browser).await;
    let parameters: CallbackParams = serde_json::from_value(Value::Object(
        callback
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
            .collect(),
    ))
    .expect("callback parameters");
    let tokens = client
        .complete(pending, &parameters)
        .await
        .expect("complete the login");
    let id_token = tokens.id_token.as_ref().expect("ID token");
    assert_eq!(id_token.user_id().expect("account"), flow.user_id);

    let access = issuer
        .resource(Resource::new(SDK_RESOURCE).expect("resource"))
        .validate::<Scopes>(tokens.access_token.expose())
        .await
        .expect("valid access token");
    assert_eq!(access.subject, Subject::User(flow.user_id));
    assert!(access.scopes.contains(Scope::OfflineAccess.as_str()));

    let user = client
        .userinfo(&tokens.access_token)
        .await
        .expect("UserInfo");
    assert_eq!(user.sub, flow.user_id.to_string());
    assert!(user.profile.email.is_some());

    let first = tokens.refresh_token.expect("refresh token");
    let rotated = client
        .refresh(&first)
        .await
        .expect("refresh")
        .refresh_token
        .expect("rotated refresh token");
    assert_ne!(rotated.expose(), first.expose());
    client.revoke(&rotated).await.expect("revoke");
    assert!(matches!(
        client.refresh(&rotated).await,
        Err(OAuthError::Rejected { response, .. })
            if response.error == OAuthCode::InvalidGrant
    ));

    let post_logout: Url = flow.client.post_logout_uris[0]
        .parse()
        .expect("post-logout URI");
    let logout = client.logout_url(id_token, &post_logout);
    let confirmation = flow
        .request(
            Method::GET,
            &format!("{}?{}", logout.path(), logout.query().expect("query")),
            &[],
            None,
        )
        .await;
    assert_eq!(confirmation.status(), StatusCode::SEE_OTHER);
    let fields: Vec<(String, String)> = logout.query_pairs().into_owned().collect();
    let fields: Vec<_> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let confirmed = flow
        .request(Method::POST, logout.path(), &fields, None)
        .await;
    assert_eq!(confirmed.status(), StatusCode::OK);
    assert_eq!(
        Flow::json(confirmed).await["redirect_url"],
        post_logout.as_str()
    );
}
