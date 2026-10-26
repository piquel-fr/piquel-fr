//! Focused parsing checks and database-backed OAuth/OIDC scenarios.

use super::*;
use crate::config::TokenDigestKey;
use crate::deliveries::{BackchannelLogoutSender, OutboundClient, Sender};
use crate::recovery::ProbationPasskey;
use crate::security::{BrowserCookie, Credential, RequestContext, Session};
use crate::tests::{AUTH_ORIGIN, Replicas, TlsListener, location, parameter, until_blocked};
use crate::{AuthConfig, federation::FederationApplication, web::WebApplication};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use piquel_common::{
    AuthenticationMethod, Handle, UserId,
    clients::{AllowedScopes, ClientKind, ClientOwner, ClientRegistration, RedirectUri, ScopeName},
    events::{Actor, DomainEvent, GrantRevocation, RevocationReason},
    protocol::{
        claims::{Acr, BACKCHANNEL_LOGOUT_EVENT, IdTokenClaims},
        step_up::StepUpRequirement,
    },
};
use piquel_common::{PasskeyId, RecoveryId};
use piquel_crypto::{KeySet, Rs256Key};
use piquel_repository::{
    BackchannelLogout, DatabaseConfig, InsertPasskey, InsertRecovery, InsertUser,
    InsertVerifiedEmail, SessionScope,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use url::Url;

/// Database-backed OIDC scenario with a provisioned client and authenticated browser.
#[derive(Clone)]
struct Flow {
    /// Application under test, sharing the scenario database.
    app: OidcApplication,
    /// Where requests go: the OIDC routes and their pages, or a replica of the whole
    /// service.
    router: axum::Router,
    /// The scenario's client, registered through [`ClientRegistry`](crate::ClientRegistry).
    client: ClientRegistration,
    /// The secret of a confidential scenario client.
    secret: Option<String>,
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
        Self::at(AUTH_ORIGIN, confidential, trusted).await
    }

    /// Like [`Self::new`], for an issuer at `origin`.
    async fn at(origin: &str, confidential: bool, trusted: bool) -> Self {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
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
                handle: Handle::parse(&format!("oidc-{}", &user_id.to_string()[24..]))
                    .expect("handle"),
                display_name: "OIDC Test".into(),
            })
            .await
            .expect("insert test account");
        tx.emails()
            .insert_verified(&InsertVerifiedEmail {
                id: piquel_common::EmailId::new(),
                user_id,
                normalized_email: format!("{user_id}@example.com"),
                is_primary: true,
                verified_at: Utc::now(),
            })
            .await
            .expect("insert verified test email");
        let cookie = Session::create(
            &mut tx,
            RequestContext::TEST,
            user_id,
            AuthenticationMethod::Passkey.into(),
        )
        .await
        .expect("create test browser session");
        let cookie = format!("{}={}", BrowserCookie::Session.as_str(), cookie.encoded());
        tx.commit().await.expect("commit test account transaction");
        let client = ClientRegistration {
            kind: if confidential {
                ClientKind::Confidential
            } else {
                ClientKind::Public
            },
            trusted,
            ..crate::tests::registration(ClientKind::Public, "https://client.example")
        };
        let secret = crate::tests::register(&db, &client)
            .await
            .expect("register test OIDC client")
            .map(|secret| secret.expose().to_owned());
        let basic = secret.as_ref().map(|secret| {
            format!(
                "{} {}",
                AuthScheme::Basic.as_str(),
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{secret}", client.id))
            )
        });
        let origin = origin
            .parse::<piquel_common::config::Origin>()
            .expect("issuer");
        let config = AuthConfig::test(&origin);
        let federation =
            FederationApplication::new(db.clone(), &config.federation).expect("federation");
        let app = OidcApplication::new(
            db.clone(),
            &OidcConfig {
                origin: origin.clone(),
                digest_keys: Arc::new(TokenDigestKeys::new(
                    TokenDigestKey::derive(&[7; 32]).expect("digest key"),
                    None,
                )),
            },
            SigningKeys::new(KeySet::single(
                Rs256Key::generate("oidc-tests").expect("RSA signing key"),
            )),
        )
        .expect("OIDC application");
        Self {
            router: WebApplication::new(db, &config, app.clone(), federation)
                .routes()
                .merge(app.clone().routes()),
            app,
            client,
            secret,
            cookie,
            user_id,
            basic,
        }
    }
    /// The same scenario, sending its requests to `router`, such as one of [`Replicas`].
    fn on(&self, router: &axum::Router) -> Self {
        Self {
            router: router.clone(),
            ..self.clone()
        }
    }
    /// Signs the scenario's browser in again with `method`, as a new session.
    async fn sign_in_again(&mut self, method: AuthenticationMethod) {
        let mut tx = self.app.database.begin().await.expect("transaction");
        let session = Session::create(&mut tx, RequestContext::TEST, self.user_id, method.into())
            .await
            .expect("session");
        tx.commit().await.expect("commit");
        self.cookie = format!("{}={}", BrowserCookie::Session.as_str(), session.encoded());
    }
    /// Lists the events recorded about the scenario account, newest first.
    async fn events(&self) -> Vec<DomainEvent> {
        self.app
            .database
            .events()
            .history_for_user(self.user_id, 100)
            .await
            .expect("history")
            .into_iter()
            .map(|stored| stored.event.known().cloned().expect("a known event"))
            .collect()
    }

    /// Dispatches an encoded protocol request, or a page's form, through the OIDC routes.
    async fn request(
        &self,
        method: Method,
        uri: &str,
        form: &[(&str, &str)],
        basic: Option<&str>,
    ) -> Response {
        let mut builder = Request::builder()
            .extension(RequestContext::TEST)
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
        self.router
            .clone()
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
        let url = self.authorization_url(scope, prompt, extra);
        if method == Method::POST {
            self.post_query(&url, None).await
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
    /// Pushes the scenario's authorization request with `basic` credentials.
    async fn push(&self, scope: &str, prompt: Option<&str>, basic: Option<&str>) -> Response {
        let mut url = self.authorization_url(scope, prompt, &[]);
        url.set_path(routes::oidc::PAR);
        self.post_query(&url, basic).await
    }
    /// Pushes the scenario's request with its credentials and returns its `request_uri`.
    async fn pushed(&self, scope: &str, prompt: Option<&str>) -> String {
        let response = self.push(scope, prompt, self.basic.as_deref()).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = Self::json(response).await;
        assert_eq!(body["expires_in"], PUSHED_REQUEST_SECONDS);
        body["request_uri"]
            .as_str()
            .expect("pushed request has a request_uri")
            .to_owned()
    }
    /// Brings a `request_uri` to the authorization endpoint as `client_id`, along
    /// with `extra` parameters, which must not override the pushed ones.
    async fn claim(&self, client_id: &str, request_uri: &str, extra: &[(&str, &str)]) -> Response {
        let mut url = Url::parse(&format!("{AUTH_ORIGIN}{}", routes::oidc::AUTHORIZE))
            .expect("parse authorization endpoint URL");
        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("request_uri", request_uri)
            .extend_pairs(extra.iter().copied());
        let uri = format!("{}?{}", url.path(), url.query().expect("query"));
        self.request(Method::GET, &uri, &[], None).await
    }
    /// Posts `url`'s query as a form to its path.
    async fn post_query(&self, url: &Url, basic: Option<&str>) -> Response {
        let owned: Vec<_> = url.query_pairs().into_owned().collect();
        let fields: Vec<_> = owned
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        self.request(Method::POST, url.path(), &fields, basic).await
    }
    /// The authorization endpoint with the scenario's request parameters, then `extra`.
    fn authorization_url(&self, scope: &str, prompt: Option<&str>, extra: &[(&str, &str)]) -> Url {
        let mut url = Url::parse(&format!("{AUTH_ORIGIN}/oauth/authorize"))
            .expect("parse authorization endpoint URL");
        url.query_pairs_mut().extend_pairs([
            ("response_type", ResponseType::Code.as_str()),
            ("client_id", self.client.id.as_str()),
            ("redirect_uri", self.client.redirect_uris[0].as_str()),
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
        url
    }
    /// Returns the valid PKCE verifier used by database-backed scenarios.
    fn verifier() -> &'static str {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    }
    /// Reads a redirect back to the client, which must name this issuer in `iss` (RFC 9207).
    fn client_redirect(&self, response: &Response) -> Url {
        self.issued(location(response))
    }
    /// Returns an authorization response URL after checking its `iss`.
    fn issued(&self, url: Url) -> Url {
        assert_eq!(parameter(&url, "iss"), self.app.issuer);
        url
    }
    /// Reads the scenario's text response.
    async fn text(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("read complete HTTP response body")
                .to_vec(),
        )
        .expect("UTF-8 response")
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
        parameter(&self.consent(response).await, "code")
    }
    /// Follows an authorization response through consent, when needed, to the client
    /// redirect, whose `iss` it checks.
    async fn consent(&self, response: Response) -> Url {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let mut destination = location(&response);
        if destination.path() == routes::page::CONSENT {
            let transaction = parameter(&destination, "transaction");
            let response = self
                .request(
                    Method::POST,
                    routes::page::CONSENT,
                    &[("transaction", &transaction), ("decision", APPROVE_CONSENT)],
                    None,
                )
                .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            destination = location(&response);
        }
        self.issued(destination)
    }
    /// Exchanges a scenario code with the requested verifier and client credentials.
    async fn exchange(&self, code: &str, verifier: &str, basic: Option<&str>) -> Response {
        self.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::AuthorizationCode.as_str()),
                ("client_id", self.client.id.as_str()),
                ("redirect_uri", self.client.redirect_uris[0].as_str()),
                ("code", code),
                ("code_verifier", verifier),
            ],
            basic,
        )
        .await
    }
    /// Verifies the ID token of a successful token response and returns the response
    /// with the token's claims.
    async fn id_token(&self, response: Response) -> (Value, Value) {
        assert_eq!(response.status(), StatusCode::OK);
        let tokens = Self::json(response).await;
        let claims = self
            .app
            .keys
            .current()
            .verify(
                tokens["id_token"].as_str().expect("ID token"),
                TokenType::Id,
                &self.app.issuer,
            )
            .expect("verify ID token");
        (tokens, claims)
    }
    /// Rotates a scenario refresh token using its registered client credentials.
    async fn refresh(&self, token: &str) -> Response {
        self.request(
            Method::POST,
            "/oauth/token",
            &[
                ("grant_type", GrantType::RefreshToken.as_str()),
                ("client_id", self.client.id.as_str()),
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
    let jwks = flow
        .request(Method::GET, routes::oidc::JWKS, &[], None)
        .await;
    assert_eq!(
        jwks.extensions().get::<CacheClass>(),
        Some(&PublicDocument::CACHE)
    );
    for path in [routes::oidc::DISCOVERY, routes::oidc::OAUTH_METADATA] {
        let response = flow.request(Method::GET, path, &[], None).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.extensions().get::<CacheClass>(),
            Some(&PublicDocument::CACHE)
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
    assert_eq!(metadata.acr_values_supported, Acr::ALL);
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
        parameter(&flow.client_redirect(&response), "error"),
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
        .current()
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
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::ConsentRequired.as_str()
    );
    let response = flow
        .authorize(Scope::OpenId.as_str(), Some(Prompt::Login.as_str()))
        .await;
    assert_eq!(location(&response).path(), "/login");
    let client_id = flow.client.id.clone();
    assert_eq!(
        flow.events().await[..3],
        [
            DomainEvent::CodeReplayed {
                client_id: client_id.clone(),
            },
            DomainEvent::GrantIssued {
                client_id: client_id.clone(),
                family_id: None,
                scopes: vec![Scope::OpenId.as_str().into()],
            },
            DomainEvent::ConsentGranted {
                client_id,
                scopes: vec![Scope::OpenId.as_str().into()],
            },
        ],
        "a failed exchange records nothing"
    );
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
        .current()
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
                ("client_id", flow.client.id.as_str()),
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
                ("client_id", flow.client.id.as_str()),
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
        .current()
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
            routes::page::LOGOUT,
            &[
                ("client_id", flow.client.id.as_str()),
                (
                    "post_logout_redirect_uri",
                    flow.client.post_logout_uris[0].as_str(),
                ),
            ],
            None,
        )
        .await;
    assert_eq!(
        location(&response).as_str(),
        flow.client.post_logout_uris[0].as_str()
    );
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
        parameter(
            &flow.client_redirect(
                &flow
                    .authorize(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
                    .await
            ),
            "error"
        ),
        OAuthCode::LoginRequired.as_str()
    );
    let events = flow.events().await;
    assert!(
        matches!(
            &events[0],
            DomainEvent::SessionRevoked {
                reason: RevocationReason::RelyingPartyLogout { client_id },
                ..
            } if *client_id == flow.client.id
        ),
        "{events:?}"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        DomainEvent::GrantRevoked {
            reason: GrantRevocation::RefreshReplay,
            ..
        }
    )));
}

/// A client's back-channel logout endpoint on a local HTTPS port: its URI, a client
/// that reaches it, and the logout tokens it received.
async fn logout_receiver() -> (RedirectUri, OutboundClient, Arc<Mutex<Vec<String>>>) {
    let posted = Arc::new(Mutex::new(Vec::new()));
    let receiver = axum::Router::new().route(
        "/backchannel-logout",
        axum::routing::post({
            let posted = Arc::clone(&posted);
            async move |axum::Form(form): axum::Form<HashMap<String, String>>| {
                posted
                    .lock()
                    .expect("posted tokens")
                    .push(form["logout_token"].clone());
                StatusCode::OK
            }
        }),
    );
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let uri = format!(
        "https://localhost:{}/backchannel-logout",
        tcp.local_addr().expect("address").port()
    )
    .parse()
    .expect("logout URI");
    let outbound = OutboundClient::local(TlsListener::serve(tcp, receiver));
    (uri, outbound, posted)
}

/// Ending a session posts a logout token to each client that received tokens from it
/// and registered a back-channel logout URI (OIDC Back-Channel Logout 1.0 §2.4):
/// signed as `logout+jwt`, naming the client, the user and the ended session, with
/// the delivery's ID as `jti`, valid for two minutes, and never with a `nonce`. A
/// client that got no tokens from the session is not told.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn logout_posts_a_logout_token_to_the_clients_of_the_session() {
    let flow = Flow::new(true, true).await;
    let (uri, outbound, posted) = logout_receiver().await;
    let sender =
        BackchannelLogoutSender::new(flow.app.issuer.clone(), flow.app.keys.clone(), outbound);
    let told = ClientRegistration {
        backchannel_logout_uri: Some(uri.clone()),
        ..flow.client.clone()
    };
    let untold = ClientRegistration {
        backchannel_logout_uri: Some(uri),
        ..crate::tests::registration(ClientKind::Public, "https://untold.example")
    };
    crate::tests::change(&flow.app.database, async |registry| {
        registry
            .update(&told.id, |_| {
                Ok::<_, crate::ClientRegistryError>(told.clone())
            })
            .await?;
        // A client without tokens from the session.
        registry.create(ClientOwner::Operator, &untold, None).await
    })
    .await
    .expect("register the logout URIs");
    let code = flow.code(Scope::OpenId.as_str()).await;
    let (_, id_token) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    let response = flow
        .request(
            Method::POST,
            routes::page::LOGOUT,
            &[("client_id", told.id.as_str())],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Other scenarios share the database: send only this session's deliveries.
    let mut sent = Vec::new();
    while let Some(delivery) = flow
        .app
        .database
        .deliveries()
        .claim::<BackchannelLogout>(std::time::Duration::from_mins(1))
        .await
        .expect("claim")
    {
        if delivery.recipient.sid.to_string() == id_token["sid"] {
            sender.send(&delivery).await.expect("the client accepts it");
            sent.push((delivery.id, delivery.recipient.client_id));
        }
    }
    let [(delivery, client)] =
        <[_; 1]>::try_from(sent).expect("one delivery for the one client told");
    assert_eq!(client, told.id);
    let [token] = <[_; 1]>::try_from(posted.lock().expect("posted tokens").clone())
        .expect("one token posted");
    let claims: Value = flow
        .app
        .keys
        .current()
        .verify(&token, TokenType::Logout, &flow.app.issuer)
        .expect("a logout token signed by auth");
    let issued_at = claims["iat"].as_i64().expect("iat");
    assert!(
        (issued_at - Utc::now().timestamp()).abs() < 60,
        "signed when sent"
    );
    assert_eq!(
        claims,
        json!({
            "iss": flow.app.issuer,
            "aud": told.id,
            "iat": issued_at,
            "exp": issued_at + 120,
            "jti": delivery,
            "sub": flow.user_id,
            "sid": id_token["sid"],
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        })
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
    let events = flow.events().await;
    let [
        DomainEvent::GrantRevoked {
            family_id: revoked,
            reason: GrantRevocation::CodeReplay,
            ..
        },
        DomainEvent::CodeReplayed { .. },
        DomainEvent::GrantIssued {
            family_id: Some(issued),
            ..
        },
        ..,
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(revoked, issued, "the replay revoked the code's own family");
}

/// The same refresh token, rotated on two replicas at once, rotates exactly once. The
/// other attempt is a replay, which revokes the family.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn concurrent_refresh_across_replicas_rotates_once() {
    let flow = Flow::new(true, true).await;
    let replicas = Replicas::new().await;
    let (a, b) = (flow.on(&replicas.a), flow.on(&replicas.b));
    let code = a.code(REFRESH_SCOPES).await;
    let response = b
        .exchange(&code, Flow::verifier(), b.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let token = Flow::json(response).await["refresh_token"]
        .as_str()
        .expect("token response contains a refresh token")
        .to_owned();
    let (first, second) = tokio::join!(a.refresh(&token), b.refresh(&token));
    let (rotated, replayed) = if first.status() == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(rotated.status(), StatusCode::OK);
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    let rotated = Flow::json(rotated).await["refresh_token"]
        .as_str()
        .expect("refresh response contains the rotated token")
        .to_owned();
    assert_eq!(
        a.refresh(&rotated).await.status(),
        StatusCode::BAD_REQUEST,
        "the replay revoked the family"
    );
}

/// A new signing key and a new token digest key leave outstanding codes and
/// refresh tokens valid, since the old digest key is still accepted. What
/// replaces them is digested under the new key alone.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn changing_keys_keeps_codes_and_refresh_tokens() {
    let flow = Flow::new(true, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let tokens = Flow::json(
        flow.exchange(
            &flow.code(REFRESH_SCOPES).await,
            Flow::verifier(),
            flow.basic.as_deref(),
        )
        .await,
    )
    .await;
    let token = tokens["refresh_token"].as_str().expect("refresh token");
    let app = OidcApplication::new(
        flow.app.database.clone(),
        &OidcConfig {
            origin: flow.app.issuer.parse().expect("issuer"),
            digest_keys: Arc::new(TokenDigestKeys::new(
                TokenDigestKey::derive(&[8; 32]).expect("new digest key"),
                Some(TokenDigestKey::derive(&[7; 32]).expect("old digest key")),
            )),
        },
        SigningKeys::new(KeySet::single(
            Rs256Key::generate("rotated").expect("new signing key"),
        )),
    )
    .expect("OIDC application");
    let changed = Flow {
        router: app.clone().routes(),
        app,
        ..flow.clone()
    };
    let exchanged = changed
        .exchange(&code, Flow::verifier(), changed.basic.as_deref())
        .await;
    assert_eq!(exchanged.status(), StatusCode::OK);
    let refreshed = changed.refresh(token).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let rotated = Flow::json(refreshed).await["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();
    assert_eq!(
        flow.refresh(&rotated).await.status(),
        StatusCode::BAD_REQUEST,
        "only the new digest key made the rotated token"
    );
    assert_eq!(changed.refresh(&rotated).await.status(), StatusCode::OK);
}

/// Checks that policy reductions reject new requests and invalidate outstanding grants,
/// and that unsafe logout redirects are refused.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn policy_reduction_blocks_outstanding_codes_and_refresh() {
    let mut flow = Flow::new(false, true).await;
    let code = flow.code(EMAIL_SCOPES).await;
    let database = flow.app.database.clone();
    flow.client.allowed_scopes =
        AllowedScopes::new([Scope::OpenId, Scope::OfflineAccess].map(ScopeName::from))
            .expect("reduced scopes");
    let client = flow.client.clone();
    crate::tests::replace(&database, &client)
        .await
        .expect("apply reduced client scope policy");
    assert_eq!(
        flow.exchange(&code, Flow::verifier(), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        parameter(
            &flow.client_redirect(&flow.authorize(EMAIL_SCOPES, None).await),
            "error"
        ),
        OAuthCode::InvalidScope.as_str()
    );
    let code = flow.code(REFRESH_SCOPES).await;
    let tokens = Flow::json(flow.exchange(&code, Flow::verifier(), None).await).await;
    flow.client.allow_refresh = false;
    let client = flow.client.clone();
    crate::tests::replace(&database, &client)
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
        .current()
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
    assert_ne!(parameter(&flow.client_redirect(&response), "code"), "");
    for (field, value) in [
        ("iss", json!("https://foreign.example")),
        ("aud", json!("other-client")),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        let hint = flow
            .app
            .keys
            .current()
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
            parameter(&flow.client_redirect(&response), "error"),
            OAuthCode::InvalidRequest.as_str()
        );
    }
    let mut other = claims;
    other["sub"] = json!(UserId::new());
    let hint = flow
        .app
        .keys
        .current()
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
        parameter(&flow.client_redirect(&response), "error"),
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
    let login = location(&response);
    assert_eq!(login.path(), "/login");
    let transaction = parameter(&login, "transaction");
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    assert_eq!(location(&response).path(), "/login");
    let response = flow
        .request(
            Method::POST,
            routes::page::CONSENT,
            &[("transaction", &transaction), ("decision", APPROVE_CONSENT)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A consent that waits for the account lock while every session ends is not
/// saved: approving reads the session again under the lock.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_consent_whose_session_ended_while_waiting_is_not_saved() {
    let flow = Flow::new(true, false).await;
    let response = flow.authorize("openid", None).await;
    let transaction = parameter(&location(&response), "transaction");
    let database = flow.app.database.clone();
    let mut holder = database.begin().await.expect("transaction");
    holder
        .users()
        .find_active_by_id_for_update(flow.user_id)
        .await
        .expect("lock")
        .expect("user");
    let approving = flow.clone();
    let decision = tokio::spawn(async move {
        let form = [
            ("transaction", transaction.as_str()),
            ("decision", APPROVE_CONSENT),
        ];
        let response = approving
            .request(Method::POST, routes::page::CONSENT, &form, None)
            .await;
        response.status()
    });
    until_blocked(&mut holder, 1).await;
    let context = RequestContext::TEST.actor(Actor::Anonymous);
    holder
        .revoke_sessions(
            &context,
            flow.user_id,
            SessionScope::All,
            &RevocationReason::Admin,
        )
        .await
        .expect("every session ends");
    holder.commit().await.expect("commit");

    assert_eq!(decision.await.expect("decision"), StatusCode::UNAUTHORIZED);
    let consents = database.oidc().list_consents(flow.user_id).await;
    assert!(consents.expect("consents").is_empty(), "not saved");
}

/// Tokens report the class and time of the grant's authentication: a refresh keeps
/// them after the session re-authenticates, and `acr_values` makes a weaker session
/// sign in again while unknown values are ignored.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn acr_targets_and_grants_keep_their_authentication() {
    let mut flow = Flow::new(true, true).await;
    let code = flow.code(REFRESH_SCOPES).await;
    let (tokens, claims) = flow
        .id_token(
            flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                .await,
        )
        .await;
    assert_eq!(claims["acr"], Acr::PhishingResistant.as_str());
    assert_eq!(claims["amr"], json!(["pop", "mfa", "user"]));
    let session = claims["sid"]
        .as_str()
        .expect("sid")
        .parse()
        .expect("session ID");
    flow.app
        .database
        .sessions()
        .confirm_passkey(
            session,
            PasskeyId::new(),
            Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("re-authenticate");
    let (_, refreshed) = flow
        .id_token(
            flow.refresh(tokens["refresh_token"].as_str().expect("refresh token"))
                .await,
        )
        .await;
    assert_eq!(refreshed["auth_time"], claims["auth_time"]);
    assert_eq!(refreshed["acr"], claims["acr"]);

    flow.sign_in_again(AuthenticationMethod::Federation).await;
    let phr = [("acr_values", "urn:example:gold phr")];
    let response = flow
        .authorize_with(
            Method::GET,
            Scope::OpenId.as_str(),
            Some(Prompt::None.as_str()),
            &phr,
        )
        .await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::LoginRequired.as_str()
    );
    let response = flow
        .authorize_with(Method::GET, Scope::OpenId.as_str(), None, &phr)
        .await;
    let login = location(&response);
    assert_eq!(login.path(), routes::page::LOGIN);
    assert_eq!(parameter(&login, "acr"), Acr::PhishingResistant.as_str());
    for acr_values in ["urn:example:gold", "urn:piquel:acr:social phr"] {
        let response = flow
            .authorize_with(
                Method::GET,
                Scope::OpenId.as_str(),
                Some(Prompt::None.as_str()),
                &[("acr_values", acr_values)],
            )
            .await;
        let code = parameter(&flow.client_redirect(&response), "code");
        let (_, claims) = flow
            .id_token(
                flow.exchange(&code, Flow::verifier(), flow.basic.as_deref())
                    .await,
            )
            .await;
        assert_eq!(claims["acr"], Acr::Social.as_str(), "{acr_values}");
        assert_eq!(claims["amr"], json!(["fed"]));
    }
}

/// A browser that signed in for an authorization with a recovered passkey during
/// its probation cannot reach `phr` by signing in again, so the client hears
/// `unmet_authentication_requirements` instead of its user looping through
/// sign-in. A social sign-in, which a passkey could still step up, and a
/// probation sign-in from before the request go to sign in, as before. Without a
/// target, a probation sign-in is enough.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_sign_in_short_of_the_target_answers_the_client() {
    let mut flow = Flow::new(true, true).await;
    flow.sign_in_again(AuthenticationMethod::Federation).await;
    let phr = [("acr_values", "phr")];
    let response = flow
        .authorize_with(Method::GET, Scope::OpenId.as_str(), None, &phr)
        .await;
    let transaction = parameter(&location(&response), "transaction");
    let resume = format!(
        "{}?transaction={transaction}",
        routes::oidc::AUTHORIZE_RESUME
    );

    flow.sign_in_again(AuthenticationMethod::Federation).await;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    assert_eq!(location(&response).path(), routes::page::LOGIN, "social");

    let database = flow.app.database.clone();
    let passkey = PasskeyId::new();
    database
        .passkeys()
        .insert(&InsertPasskey {
            id: passkey,
            credential_id: passkey.as_uuid().as_bytes().to_vec(),
            user_id: flow.user_id,
            credential: json!({}),
            friendly_name: "Recovered".into(),
        })
        .await
        .expect("passkey");
    let recovery = RecoveryId::new();
    database
        .recoveries()
        .insert(&InsertRecovery {
            id: recovery,
            user_id: flow.user_id,
            secret_digest: &recovery.as_uuid().as_bytes().repeat(2),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .expect("recovery");
    let probation = crate::recovery::PROBATION;
    let mut recoveries = database.recoveries();
    let completed = recoveries
        .complete(flow.user_id, recovery, passkey, probation)
        .await;
    assert!(completed.expect("complete"));
    let stored = recoveries
        .find(recovery)
        .await
        .expect("lookup")
        .expect("recovery");
    let credential = Credential::Probation(ProbationPasskey::of(&stored).expect("probation"));
    let user_id = flow.user_id;
    let probation_sign_in = || async {
        let mut tx = database.begin().await.expect("transaction");
        let session = Session::create(&mut tx, RequestContext::TEST, user_id, credential).await;
        tx.commit().await.expect("commit");
        let cookie = BrowserCookie::Session.as_str();
        format!("{cookie}={}", session.expect("session").encoded())
    };
    let before_the_request = probation_sign_in().await;
    let response = flow
        .authorize_with(Method::GET, Scope::OpenId.as_str(), None, &phr)
        .await;
    let transaction = parameter(&location(&response), "transaction");
    let resume = format!(
        "{}?transaction={transaction}",
        routes::oidc::AUTHORIZE_RESUME
    );
    flow.cookie = before_the_request;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    assert_eq!(location(&response).path(), routes::page::LOGIN, "not fresh");

    flow.cookie = probation_sign_in().await;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    assert_eq!(
        parameter(&flow.client_redirect(&response), "error"),
        OAuthCode::UnmetAuthenticationRequirements.as_str()
    );
    // Signing in again for a request without a target is enough.
    let response = flow.authorize(Scope::OpenId.as_str(), Some("login")).await;
    let transaction = parameter(&location(&response), "transaction");
    let resume = format!(
        "{}?transaction={transaction}",
        routes::oidc::AUTHORIZE_RESUME
    );
    flow.cookie = probation_sign_in().await;
    let response = flow.request(Method::GET, &resume, &[], None).await;
    let code = parameter(&flow.client_redirect(&response), "code");
    assert!(!code.is_empty(), "no target, no refusal");
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
            parameter(&flow.client_redirect(&response), "error"),
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
        discovery["pushed_authorization_request_endpoint"],
        format!("{}{}", flow.app.issuer, routes::oidc::PAR)
    );
    // Only pushed requests have a request_uri, and no redirect URI is known for it.
    let response = flow
        .claim(
            flow.client.id.as_str(),
            "https://example.com/request.jwt",
            &[],
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidRequestUri.as_str()
    );
    assert_eq!(
        discovery["authorization_response_iss_parameter_supported"],
        true
    );
    let response = flow
        .authorize_with(Method::POST, PROFILE_SCOPES, None, &[])
        .await;
    let code = parameter(&flow.client_redirect(&response), "code");
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
            &[("client_id", flow.client.id.as_str())],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidRequest.as_str()
    );
}

/// A pushed request is validated like a browser one, but answers in JSON. Its
/// `request_uri` is not a transaction: only its client can claim it, once, and the
/// query cannot override what was pushed, `prompt` included. A client required to
/// push cannot send plain requests.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pushed_requests_are_one_time_client_bound_and_authoritative() {
    let mut flow = Flow::new(true, false).await;
    let id = flow.client.id.to_string();
    let response = flow.push(Scope::OpenId.as_str(), None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = flow
        .push("openid unregistered", None, flow.basic.as_deref())
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Flow::json(response).await["error"],
        OAuthCode::InvalidScope.as_str()
    );
    let request_uri = flow
        .pushed(Scope::OpenId.as_str(), Some(Prompt::None.as_str()))
        .await;
    assert_eq!(
        parameter(
            &flow.client_redirect(&flow.claim(&id, &request_uri, &[]).await),
            "error"
        ),
        OAuthCode::ConsentRequired.as_str()
    );
    let request_uri = flow.pushed(Scope::OpenId.as_str(), None).await;
    let transaction = request_uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .expect("RFC 9126 request_uri");
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rejected = async |client_id: &str, request_uri: &str| {
        let response = flow.claim(client_id, request_uri, &[]).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            Flow::json(response).await["error"],
            OAuthCode::InvalidRequestUri.as_str()
        );
    };
    let other = crate::tests::registration(ClientKind::Public, "https://other.example");
    crate::tests::register(&flow.app.database, &other)
        .await
        .expect("register another client");
    rejected(other.id.as_str(), &request_uri).await;
    rejected(&id, "urn:ietf:params:oauth:request_uri:unknown").await;
    rejected(&id, "https://client.example/request.jwt").await;
    let response = flow
        .claim(
            &id,
            &request_uri,
            &[
                ("scope", EMAIL_SCOPES),
                ("state", "forged-state"),
                ("redirect_uri", "https://evil.example/callback"),
                ("prompt", Prompt::None.as_str()),
            ],
        )
        .await;
    let redirect = flow.consent(response).await;
    assert_eq!(
        redirect.origin(),
        Url::parse(flow.client.redirect_uris[0].as_str())
            .expect("callback")
            .origin()
    );
    assert_eq!(parameter(&redirect, "state"), "test-state");
    let code = parameter(&redirect, "code");
    let response = flow
        .exchange(&code, Flow::verifier(), flow.basic.as_deref())
        .await;
    let (tokens, claims) = flow.id_token(response).await;
    assert_eq!(tokens["scope"], Scope::OpenId.as_str());
    assert_eq!(claims["nonce"], "test-nonce");
    rejected(&id, &request_uri).await;
    flow.client.require_pushed_authorization_requests = true;
    let client = flow.client.clone();
    crate::tests::replace(&flow.app.database, &client)
        .await
        .expect("require pushed requests");
    assert_eq!(
        parameter(
            &flow.client_redirect(&flow.authorize(Scope::OpenId.as_str(), None).await),
            "error"
        ),
        OAuthCode::InvalidRequest.as_str()
    );
    let request_uri = flow.pushed(Scope::OpenId.as_str(), None).await;
    // The user consented above, so the claim returns a code at once.
    let response = flow.claim(&id, &request_uri, &[]).await;
    parameter(&flow.client_redirect(&response), "code");
}

/// A pushed `prompt=login` needs a sign-in after the browser claims the request:
/// one between the push and the claim is not fresh.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn pushed_requests_count_sign_in_freshness_from_the_claim() {
    let mut flow = Flow::new(true, false).await;
    let request_uri = flow
        .pushed(Scope::OpenId.as_str(), Some(Prompt::Login.as_str()))
        .await;
    flow.sign_in_again(AuthenticationMethod::Passkey).await;
    let response = flow.claim(flow.client.id.as_str(), &request_uri, &[]).await;
    let location = location(&response);
    assert_eq!(location.path(), "/login");
    let transaction = parameter(&location, "transaction");
    flow.sign_in_again(AuthenticationMethod::Passkey).await;
    let response = flow
        .request(
            Method::GET,
            &format!("/oauth/authorize/resume?transaction={transaction}"),
            &[],
            None,
        )
        .await;
    parameter(&flow.consent(response).await, "code");
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
        AuthorizeRequest, CallbackParams, ClientConfig, Credentials, LoginError, OAuthError,
        Resource, Scopes, Subject,
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
    let issuer = piquel_auth::Issuer::builder()
        .http_client(http)
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
        .resource(Resource::new(flow.client.id.as_str()).expect("resource"))
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
        .as_str()
        .parse()
        .expect("post-logout URI");
    let logout = client.logout_url(id_token, Some(&post_logout));
    let confirmation = location(
        &flow
            .request(
                Method::GET,
                &format!("{}?{}", logout.path(), logout.query().expect("query")),
                &[],
                None,
            )
            .await,
    );
    assert_eq!(confirmation.path(), routes::page::LOGOUT);
    let fields: Vec<(String, String)> = confirmation.query_pairs().into_owned().collect();
    let fields: Vec<_> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let confirmed = flow
        .request(Method::POST, routes::page::LOGOUT, &fields, None)
        .await;
    assert_eq!(location(&confirmed), post_logout);
}

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
            axum::{BearerLayer, LoginRoutes, MemoryBackend, RequireAuthentication, SignedIn},
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
                        format!("Bearer {}", user.login().access_token.expose()),
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
        let auth = LoginRoutes::new(client, MemoryBackend::default())
            .scopes("profile offline_access".parse().expect("scopes"))
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
                    user.login().access_token.expose().to_owned()
                }),
            )
            .route("/settings", axum::routing::get(call_api("/settings")))
            .route("/stubborn", axum::routing::get(call_api("/stubborn")))
            .nest("/auth", auth.router())
            .layer(auth.layer());
        Self { flow, app, clock }
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
        (
            Self::cookie(&start, "__Host-piquel-login"),
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
/// store, refresh them there, rotate the session on every sign-in, refuse open
/// redirects, and log out through the provider.
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
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-piquel-session=")
                && cookie.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=43200"))
    );
    assert!(cookies.iter().any(|cookie| cookie
        == "__Host-piquel-login=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"));
    let first = LoginApp::cookie(&callback, "__Host-piquel-session");
    let shown = app.send(Method::GET, "/notes", Some(&first)).await;
    assert_eq!(shown.status(), StatusCode::OK);
    let access = Flow::text(shown).await;

    // A second sign-in rotates the session and ends the first one.
    let callback = app.sign_in("/auth/login", Some(&first)).await;
    assert_eq!(LoginApp::location(&callback), "/");
    let second = LoginApp::cookie(&callback, "__Host-piquel-session");
    assert_ne!(first, second);
    let stale = app.send(Method::GET, "/notes", Some(&first)).await;
    assert_eq!(LoginApp::location(&stale), "/auth/login?return_to=%2Fnotes");

    // Near expiry, the access token is refreshed in the store.
    app.clock.advance(290);
    let refreshed = app.send(Method::GET, "/notes", Some(&second)).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
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
            .any(|cookie| cookie.starts_with("__Host-piquel-session=;"))
    );
    let after = app.send(Method::GET, "/notes", Some(&second)).await;
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
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
    let first = LoginApp::cookie(&callback, "__Host-piquel-session");

    let page = app.send(Method::GET, "/settings", Some(&first)).await;
    let login = LoginApp::location(&page);
    assert_eq!(
        login,
        "/auth/login?return_to=%2Fsettings&acr_values=phr&max_age=300&step_up=true"
    );
    let (pending, authorize) = app.start_login(&login, Some(&first)).await;
    assert_eq!(parameter(&authorize, "acr_values"), "phr");
    assert_eq!(parameter(&authorize, "max_age"), "300");
    // The social session is too weak, so the provider asks for a passkey.
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
    let browser = app.authorize(&authorize).await;
    let callback = app.finish_login(browser, pending, Some(&first)).await;
    assert_eq!(LoginApp::location(&callback), "/settings");
    let second = LoginApp::cookie(&callback, "__Host-piquel-session");
    let retry = LoginApp::cookie(&callback, "__Host-piquel-step-up");

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
            .any(|cookie| cookie.starts_with("__Host-piquel-step-up=;")),
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
    let third = LoginApp::cookie(&callback, "__Host-piquel-session");
    let retry = LoginApp::cookie(&callback, "__Host-piquel-step-up");
    let cookies = format!("{third}; {retry}");
    // Only the returning `GET` is the retry.
    let other = app.send(Method::POST, "/stubborn", Some(&cookies)).await;
    assert_eq!(LoginApp::cookies(&other), Vec::<String>::new());
    let refused = app.send(Method::GET, "/stubborn", Some(&cookies)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    // An ordinary sign-in drops a marker its return never used.
    let page = app.send(Method::GET, "/stubborn", Some(&third)).await;
    let callback = app.sign_in(&LoginApp::location(&page), Some(&third)).await;
    let fourth = LoginApp::cookie(&callback, "__Host-piquel-session");
    let unused = LoginApp::cookie(&callback, "__Host-piquel-step-up");
    let callback = app.sign_in("/auth/login", Some(&fourth)).await;
    assert!(
        LoginApp::cookies(&callback)
            .iter()
            .any(|cookie| cookie.starts_with("__Host-piquel-step-up=;")),
        "the unused marker {unused} is dropped"
    );
}
