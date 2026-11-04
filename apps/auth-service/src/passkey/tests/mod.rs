//! Focused name validation and database-backed `WebAuthn` ceremony invariants.

use super::*;
use crate::{
    account::AccountApplication,
    tests::{AUTH_ORIGIN, Browser, Replicas},
};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
};
use piquel_common::{TokenId, events::SignInFailure, protocol::claims::Acr};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseConfig, SessionAuthentication, StoredSession};
use serde_json::json;
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

mod confirmation;
mod counters;
mod registration;
mod related_pages;
mod sign_in;
mod telemetry;
mod validation;

/// Maximum JSON response accepted by the software browser fixture.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Isolated account and counter-capable software authenticator for database
/// scenarios. The recovery scenarios use it too.
pub(crate) struct Fixture {
    /// Routes and persistence under test.
    app: PasskeyApplication,
    /// Where requests go: the passkey routes, or a replica of the whole service.
    router: axum::Router,
    /// Software credential capable of user verification and monotonic counters.
    authenticator: WebauthnAuthenticator<SoftPasskey>,
    /// HTTPS origin passed to the authenticator.
    origin: Url,
    /// Seeded account owning the software credential.
    pub(crate) user_id: UserId,
    /// Seeded passkey row used for rename and last-key removal checks.
    pub(crate) key_id: PasskeyId,
    /// Unique seeded username for identified authentication.
    pub(crate) username: String,
    /// The signing credential's ID, which an account picker's challenge lists.
    credential_id: Vec<u8>,
}
impl Fixture {
    /// Seeds an account and passkey in the explicitly configured isolated database.
    pub(crate) async fn new() -> Self {
        let url = piquel_common::config::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("isolated test database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let origin = Url::parse(AUTH_ORIGIN).expect("origin");
        let config = crate::AuthConfig::test(&AUTH_ORIGIN.parse().expect("origin"));
        let keys = crate::KeyStore::new(database.clone(), Arc::clone(&config.key_encryption_key))
            .start()
            .await
            .expect("signing keys");
        let oidc = OidcApplication::new(database.clone(), &config.oidc, keys).expect("OIDC app");
        let app = PasskeyApplication::new(database, &config.passkey, oidc).expect("passkey app");
        let user_id = UserId::new();
        let username = format!("key-{}", &TokenId::new().to_string()[24..]);
        app.database
            .users()
            .insert(&InsertUser {
                id: user_id,
                handle: Handle::parse(&username).expect("handle"),
                display_name: "Test user".into(),
            })
            .await
            .expect("user");
        let (key_id, credential_id, authenticator) =
            Self::seed_passkey(&app, &origin, user_id, &username, "Original key").await;
        Self {
            router: app
                .clone()
                .routes()
                .merge(AccountApplication::new(app.database.clone()).routes()),
            app,
            authenticator,
            origin,
            user_id,
            key_id,
            username,
            credential_id,
        }
    }
    /// Stores a new software authenticator's passkey named `name` for `user_id`.
    /// The authenticator supports UV and signed counters, but not resident
    /// credentials. Browser tests cover production resident signup; this uses the
    /// library's normal registration.
    async fn seed_passkey(
        app: &PasskeyApplication,
        origin: &Url,
        user_id: UserId,
        username: &str,
        name: &str,
    ) -> (PasskeyId, Vec<u8>, WebauthnAuthenticator<SoftPasskey>) {
        let (challenge, state) = app
            .webauthn
            .start_passkey_registration(user_id.as_uuid(), username, "Test user", None)
            .expect("registration");
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = authenticator
            .do_registration(origin.clone(), challenge)
            .expect("software registration");
        let key = app
            .webauthn
            .finish_passkey_registration(&registration, &state)
            .expect("verified registration");
        let id = PasskeyId::new();
        let credential_id = key.cred_id().as_ref().to_vec();
        app.database
            .passkeys()
            .insert(&InsertPasskey {
                id,
                credential_id: credential_id.clone(),
                user_id,
                credential: serde_json::to_value(key).expect("credential"),
                friendly_name: name.into(),
            })
            .await
            .expect("stored key");
        (id, credential_id, authenticator)
    }
    /// Signs with `authenticator` from now on, and returns the one that signed
    /// until now.
    pub(crate) fn replace_authenticator(
        &mut self,
        authenticator: WebauthnAuthenticator<SoftPasskey>,
    ) -> WebauthnAuthenticator<SoftPasskey> {
        std::mem::replace(&mut self.authenticator, authenticator)
    }
    /// Stores another passkey named `name` on the account, and signs with it from
    /// now on.
    pub(crate) async fn switch_passkey(&mut self, name: &str) -> PasskeyId {
        let (id, credential_id, authenticator) =
            Self::seed_passkey(&self.app, &self.origin, self.user_id, &self.username, name).await;
        self.authenticator = authenticator;
        self.credential_id = credential_id;
        id
    }
    /// Sends the next requests to `router`, such as one of [`Replicas`].
    fn on(&mut self, router: &axum::Router) -> &mut Self {
        self.router = router.clone();
        self
    }
    /// The scenario database.
    pub(crate) const fn database(&self) -> &Database {
        &self.app.database
    }
    /// Sends a JSON request from the auth origin with the supplied cookies.
    pub(crate) async fn request(
        &self,
        path: &str,
        method: Method,
        cookies: &str,
        body: Value,
    ) -> Response {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::ORIGIN, AUTH_ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookies);
        self.send(request, body.to_string()).await
    }
    /// Sends `request` with the CSRF header and `body`.
    async fn send(&self, request: axum::http::request::Builder, body: String) -> Response {
        self.router
            .clone()
            .oneshot(
                request
                    .extension(crate::security::RequestContext::TEST)
                    .header("x-piquel-csrf", "1")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response")
    }
    /// Starts a ceremony and returns its challenge JSON and browser-binding cookie.
    pub(crate) async fn start(&self, path: &str, cookies: &str, body: Value) -> (Value, String) {
        let response = self.request(path, Method::POST, cookies, body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = Self::cookie(&response);
        (Self::json(response).await, cookie)
    }
    /// Reads a response's JSON body.
    pub(crate) async fn json(response: Response) -> Value {
        serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                .await
                .expect("body"),
        )
        .expect("JSON")
    }
    /// Extracts the cookie pair from a response for the next simulated browser request.
    pub(crate) fn cookie(response: &Response) -> String {
        response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_owned()
    }
    /// Signs a started authentication challenge using the software credential.
    pub(crate) fn assertion(&mut self, started: &Value) -> PublicKeyCredential {
        self.assertion_for(self.origin.clone(), started)
    }
    /// Signs a started authentication challenge for a page on `origin`, within
    /// auth's RP ID. The software credential is not discoverable, so an account
    /// picker's challenge gets it listed, and the answer names its account as a
    /// discoverable one would.
    fn assertion_for(&mut self, origin: Url, started: &Value) -> PublicKeyCredential {
        let mut challenge: RequestChallengeResponse =
            serde_json::from_value(started["public_key"].clone())
                .expect("authentication challenge");
        let picker = challenge.public_key.allow_credentials.is_empty();
        if picker {
            challenge.public_key.allow_credentials = vec![webauthn_rs_proto::AllowCredentials {
                type_: "public-key".into(),
                id: self.credential_id.clone().into(),
                transports: None,
            }];
        }
        let mut credential = self
            .authenticator
            .do_authentication(origin, challenge)
            .expect("software assertion");
        if picker {
            credential.response.user_handle =
                Some(self.user_id.as_uuid().as_bytes().to_vec().into());
        }
        credential
    }
    /// Completes an identified login and returns the new session cookie.
    async fn login(&mut self) -> String {
        self.login_from("").await
    }
    /// Completes an identified login in a browser holding the `session` cookie pair,
    /// if any, and returns the session cookie it sets.
    async fn login_from(&mut self, session: &str) -> String {
        let (started, browser) = self
            .start(
                "/webauthn/authenticate/start",
                "",
                json!({"handle":self.username}),
            )
            .await;
        let assertion = self.assertion(&started);
        let response = self
            .request(
                "/webauthn/authenticate/finish",
                Method::POST,
                &format!("{session}; {browser}"),
                json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Self::cookie(&response)
    }
    /// Finds the active session a cookie pair names.
    pub(crate) async fn session(&self, cookie: &str) -> Option<StoredSession> {
        let secret = cookie
            .split_once('=')
            .and_then(|(_, value)| Secret::parse(value).ok())
            .expect("session cookie");
        self.app
            .database
            .sessions()
            .find_active_by_browser_secret(secret.digest().as_bytes())
            .await
            .expect("session lookup")
    }
    /// Lists the events recorded about the seeded account, newest first.
    pub(crate) async fn events(&self) -> Vec<DomainEvent> {
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
    /// Answers a started registration challenge with a fresh software credential.
    pub(crate) fn credential(&self, started: &Value) -> RegisterPublicKeyCredential {
        self.new_authenticator(started).0
    }
    /// Answers a started registration challenge with a new software
    /// authenticator, and returns the credential and the authenticator, which can
    /// sign with it once stored as [`Self::authenticator`].
    pub(crate) fn new_authenticator(
        &self,
        started: &Value,
    ) -> (
        RegisterPublicKeyCredential,
        WebauthnAuthenticator<SoftPasskey>,
    ) {
        let challenge =
            serde_json::from_value(started["public_key"].clone()).expect("registration challenge");
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(self.origin.clone(), challenge)
            .expect("software registration");
        (credential, authenticator)
    }
}
