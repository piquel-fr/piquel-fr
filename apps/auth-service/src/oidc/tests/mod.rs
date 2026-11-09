//! Focused parsing checks and database-backed OAuth/OIDC scenarios.

use super::*;
use crate::config::TokenDigestKey;
use crate::security::{BrowserCookie, RequestContext, Session};
use crate::tests::{
    AUTH_ORIGIN, Browser, Replicas, TlsListener, location, parameter, until_blocked,
    verified_address,
};
use crate::{AuthConfig, federation::FederationApplication, web::WebApplication};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use sourceorigin_common::{
    AuthenticationMethod, Handle, PasskeyId, UserId,
    clients::{ClientKind, ClientRegistration},
    events::{Actor, CodeRedemptionFailure, DomainEvent, RevocationReason},
    protocol::claims::{Acr, IdTokenClaims},
};
use sourceorigin_crypto::{KeySet, Rs256Key};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use url::Url;

mod app_removal;
mod authorization;
mod logout;
mod policy;
mod protocol;
mod pushed;
mod sdk_client;
mod sdk_routes;
mod step_up;
mod tokens;

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
        let db = Replicas::database().await;
        let browser = Browser::new_account(&db).await;
        let (user_id, cookie) = (browser.user_id, browser.cookie);
        verified_address(&db, user_id, &format!("{user_id}@example.com"), true).await;
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
            .parse::<sourceorigin_common::config::Origin>()
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
                policies: config.oidc.policies.clone(),
            },
            SigningKeys::new(KeySet::single(
                Rs256Key::generate("oidc-tests").expect("RSA signing key"),
            )),
        )
        .expect("OIDC application");
        let passkeys = config.passkeys(db.clone(), app.clone()).expect("passkeys");
        Self {
            router: WebApplication::new(db, &config, app.clone(), federation, passkeys)
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
            .header("x-sourceorigin-csrf", "1");
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
                &sourceorigin_crypto::Pkce::challenge(Self::verifier()).expect("PKCE"),
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
            .expect("fresh keys")
            .verify(
                tokens["id_token"].as_str().expect("ID token"),
                TokenType::Id,
                &self.app.issuer,
            )
            .expect("verify ID token");
        (tokens, claims)
    }
    /// The scenario's account, as the owner of its browser session.
    async fn owner(&self) -> crate::account::Owner {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::COOKIE, self.cookie.parse().expect("cookie"));
        crate::account::AccountService::new(self.app.database.clone())
            .owner(RequestContext::TEST, &headers)
            .await
            .expect("session lookup")
            .expect("signed in")
    }
    /// Asserts that a token response rejected its grant as `invalid_grant`.
    async fn assert_invalid_grant(response: Response) {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            Self::json(response).await["error"],
            OAuthCode::InvalidGrant.as_str()
        );
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

/// Existing scope strings exercise the HTTP wire contract independently of enum serialization.
const EMAIL_REFRESH_SCOPES: &str = "openid email offline_access";
/// Identity and session-bounded refresh requested together.
const REFRESH_SCOPES: &str = "openid offline_access";
/// Public-profile scope fixture.
const PROFILE_SCOPES: &str = "openid profile";
/// Profile claims with a refresh token.
const PROFILE_REFRESH_SCOPES: &str = "openid profile offline_access";
/// Verified-email scope fixture.
const EMAIL_SCOPES: &str = "openid email";
/// Unregistered extension scope fixture used to check rejection.
const UNGRANTED_SCOPES: &str = "openid admin";

/// Existing approve form spelling, independent of the JSON-only consent enum.
const APPROVE_CONSENT: &str = "approve";
