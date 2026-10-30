//! Focused name validation and database-backed `WebAuthn` ceremony invariants.

use super::*;
use crate::{
    account::AccountApplication,
    tests::{AUTH_ORIGIN, Browser, OWN_PAGE, Replicas, change, pending_sign_in, register},
};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
};
use piquel_common::{
    TokenId,
    events::{RevocationReason, SignInFailure},
    protocol::claims::{Acr, Amr},
};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseConfig, SessionAuthentication, StoredSession};
use serde_json::json;
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

/// Maximum JSON response accepted by the software browser fixture.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Names count Unicode characters, preserve spacing and reject blank/control input.
#[test]
fn display_and_passkey_names_share_unicode_validation() {
    for valid in [" Alice ".to_owned(), "é".repeat(80)] {
        assert_eq!(
            DisplayName::parse(valid.clone())
                .expect("display name")
                .as_str(),
            valid
        );
        assert_eq!(
            PasskeyName::parse(valid.clone())
                .expect("passkey name")
                .as_str(),
            valid
        );
    }
    for invalid in [String::new(), " \t ".into(), "a\0b".into(), "é".repeat(81)] {
        assert!(matches!(
            DisplayName::parse(invalid.clone()),
            Err(PasskeyError::InvalidDisplayName)
        ));
        assert!(matches!(
            PasskeyName::parse(invalid),
            Err(PasskeyError::InvalidPasskeyName)
        ));
    }
}

/// Typed payloads retain the stored ceremony representation and reject wrong consumers.
#[test]
fn typed_ceremonies_preserve_persistence_and_check_the_expected_payload() {
    use ceremonies::CeremonyState;

    let user_id = UserId::new();
    let session_id = piquel_common::SessionId::new();
    let origin = Url::parse("https://auth.piquel.fr").expect("origin");
    let webauthn = WebauthnBuilder::new("auth.piquel.fr", &origin)
        .expect("builder")
        .build()
        .expect("WebAuthn");
    let (_, state) = webauthn
        .start_discoverable_authentication()
        .expect("challenge");
    let encoded_state = serde_json::to_value(&state).expect("state");
    let ceremony = Ceremony::Discover(DiscoverCeremony { state });
    assert_eq!(
        ceremony.kind(),
        piquel_repository::CeremonyKind::Authentication
    );
    let encoded = serde_json::to_value(ceremony).expect("ceremony");
    assert_eq!(encoded, json!({"Discover":{"state":encoded_state}}));
    let stored = || serde_json::from_value(encoded.clone()).expect("stored ceremony");
    assert!(AuthenticationCeremony::extract(stored()).is_some());
    assert!(RegistrationCeremony::extract(stored()).is_none());
    assert!(EnrollmentCeremony::extract(stored()).is_none());
    assert!(ConfirmationCeremony::extract(stored()).is_none());

    let (_, state) = webauthn
        .start_passkey_registration(user_id.as_uuid(), "alice", "Alice", None)
        .expect("registration");
    let enrollment = Ceremony::Enroll(EnrollmentCeremony {
        user_id,
        session_id,
        state,
    });
    assert_eq!(enrollment.kind(), EnrollmentCeremony::KIND);
    assert!(EnrollmentCeremony::extract(enrollment).is_some());
}

/// Sign-in and confirmation accept only an active account's passkey; the
/// owner's undo of a recovery accepts a disabled account's too, without a
/// credential to sign in with. An account being deleted has nothing to accept.
#[test]
fn only_an_undo_accepts_a_disabled_accounts_passkey() {
    let passkey = PasskeyId::new();
    let credential = Credential::Passkey(passkey);
    let signs_in = |status| <Credential as Acceptance>::accept(status, passkey, credential);
    assert_eq!(signs_in(AccountStatus::Active).ok(), Some(credential));
    for status in [AccountStatus::Disabled, AccountStatus::Deleting] {
        assert!(matches!(
            signs_in(status),
            Err(PasskeyError::AccountInactive)
        ));
    }
    let undoes = |status| <Accepted as Acceptance>::accept(status, passkey, credential);
    assert!(matches!(undoes(AccountStatus::Active), Ok(Accepted::Active(id)) if id == passkey));
    assert!(matches!(undoes(AccountStatus::Disabled), Ok(Accepted::Disabled(id)) if id == passkey));
    assert!(matches!(
        undoes(AccountStatus::Deleting),
        Err(PasskeyError::AccountInactive)
    ));
}

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
    /// Registers a new account with a fresh software credential; returns the finish response.
    async fn register(&self, cookies: &str, body: Value) -> Response {
        let (started, browser) = self.start("/webauthn/register/start", cookies, body).await;
        let credential = self.credential(&started);
        self.request(
            "/webauthn/register/finish",
            Method::POST,
            &format!("{cookies}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":credential}),
        )
        .await
    }
}

/// Signup normalizes the handle, and refuses invalid, reserved and taken ones with
/// their codes; whether a handle is taken, only once admitted.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signup_applies_the_handle_rules() {
    let mut fixture = Fixture::new().await;
    for (handle, status, code) in [
        ("a_b", StatusCode::BAD_REQUEST, "handle_invalid"),
        ("adm1n", StatusCode::BAD_REQUEST, "handle_reserved"),
        (
            fixture.username.as_str(),
            StatusCode::CONFLICT,
            "handle_taken",
        ),
    ] {
        let response = fixture
            .request(
                "/webauthn/register/start",
                Method::POST,
                "",
                json!({"handle": handle}),
            )
            .await;
        assert_eq!(response.status(), status, "{handle}");
        assert_eq!(Fixture::json(response).await["code"], code, "{handle}");
    }
    let (started, _) = fixture
        .start(
            "/webauthn/register/start",
            "",
            json!({"handle": " New-User "}),
        )
        .await;
    assert_eq!(
        started["public_key"]["publicKey"]["user"]["name"],
        "new-user"
    );
    // Only an admitted signup learns whether a handle is held.
    let invite_only = PasskeyApplication::new(
        fixture.app.database.clone(),
        &PasskeyConfig {
            origin: AUTH_ORIGIN.parse().expect("origin"),
            invite_required: true,
        },
        fixture.app.oidc.clone(),
    )
    .expect("passkey app");
    let taken = json!({"handle": fixture.username});
    let response = fixture
        .on(&invite_only.routes())
        .request("/webauthn/register/start", Method::POST, "", taken)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Checks that abandoned social signup state never attaches to unrelated registration.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn registration_attaches_a_pending_social_signup_only_when_it_names_it() {
    let fixture = Fixture::new().await;
    let secret = Secret::generate().expect("browser secret");
    let pending = pending_sign_in(&secret);
    let database = fixture.app.database.clone();
    database
        .federation()
        .insert_pending(&pending)
        .await
        .expect("pending signup");
    let social = format!(
        "{}={}",
        BrowserCookie::FederationPending.as_str(),
        secret.encoded()
    );
    let response = fixture
        .request(
            "/webauthn/register/start",
            Method::POST,
            &social,
            json!({"handle":"unrelated","pending_signup":TokenId::new()}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    for (explicit, attached) in [(None, false), (Some(pending.id), true)] {
        let username = format!("reg-{}", &TokenId::new().to_string()[24..]);
        let response = fixture
            .register(
                &social,
                json!({"handle":username,"pending_signup":explicit}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let user = database
            .users()
            .find_active_by_handle(&Handle::parse(&username).expect("handle"))
            .await
            .expect("user")
            .expect("registered");
        let owner = database
            .federation()
            .find_active(&pending.issuer, &pending.subject)
            .await
            .expect("identity")
            .map(|identity| identity.user_id);
        assert_eq!(owner, attached.then_some(user.id), "{username}");
        let passkeys = database.passkeys().list_active(user.id).await;
        let sessions = database.sessions().list_active_for_user(user.id).await;
        let [session] = &sessions.expect("sessions")[..] else {
            panic!("one session");
        };
        let recorded = database.sessions().passkey(session.id).await;
        let [passkey] = &passkeys.expect("passkeys")[..] else {
            panic!("one passkey");
        };
        assert_eq!(
            recorded.expect("passkey"),
            Some(passkey.id),
            "signed in by it"
        );
    }
}

/// Checks counter ordering under concurrent ceremony snapshots, records the
/// regression and prevents replay.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn overlapping_assertions_reject_old_counter_after_new_counter_commits() {
    let mut fixture = Fixture::new().await;
    let (older, browser) = fixture
        .start(
            "/webauthn/authenticate/start",
            "",
            json!({"handle":fixture.username}),
        )
        .await;
    let (newer, _) = fixture
        .start(
            "/webauthn/authenticate/start",
            &browser,
            json!({"handle":fixture.username}),
        )
        .await;
    let older_assertion = fixture.assertion(&older);
    let newer_assertion = fixture.assertion(&newer);
    let newer_body = json!({"ceremony_id":newer["ceremony_id"],"credential":newer_assertion});
    let response = fixture
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            newer_body.clone(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = fixture
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            json!({"ceremony_id":older["ceremony_id"],"credential":older_assertion}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let response = fixture
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            newer_body,
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "ceremony cannot replay"
    );
    let keys = fixture
        .app
        .database
        .passkeys()
        .list_active(fixture.user_id)
        .await
        .expect("keys");
    assert_eq!(
        keys[0].credential.pointer(CREDENTIAL_COUNTER_POINTER),
        Some(&json!(2))
    );
    let events = fixture.events().await;
    assert!(
        matches!(
            events.as_slice(),
            [
                DomainEvent::SignInFailed {
                    method: AuthenticationMethod::Passkey,
                    reason: SignInFailure::CounterRegression,
                },
                DomainEvent::SignedIn {
                    method: AuthenticationMethod::Passkey,
                    ..
                },
            ]
        ),
        "the regression outlives its rolled-back authentication transaction; the replay is not recorded: {events:?}"
    );
}

/// A copy of a passkey that signs behind the stored counter is rejected by `WebAuthn`'s
/// snapshot check, and the rejection is recorded like the locked check.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn lagging_counter_copy_is_rejected_and_recorded() {
    let mut fixture = Fixture::new().await;
    // Simulate the original authenticator having signed far ahead of this copy.
    let mut passkeys = fixture.app.database.passkeys();
    let mut key = passkeys
        .list_active(fixture.user_id)
        .await
        .expect("keys")
        .remove(0);
    *key.credential
        .pointer_mut(CREDENTIAL_COUNTER_POINTER)
        .expect("counter") = json!(100);
    assert!(
        passkeys
            .update_after_authentication(&key.credential_id, &key.credential)
            .await
            .expect("advanced counter")
    );
    let (started, browser) = fixture
        .start(
            "/webauthn/authenticate/start",
            "",
            json!({"handle":fixture.username}),
        )
        .await;
    let assertion = fixture.assertion(&started);
    let response = fixture
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        fixture.events().await,
        [DomainEvent::SignInFailed {
            method: AuthenticationMethod::Passkey,
            reason: SignInFailure::CounterRegression,
        }]
    );
}

/// Checks browser binding, and that a passkey confirmation belongs to one session,
/// counts from its own time and is required only where an action needs it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
#[expect(
    clippy::too_many_lines,
    reason = "Keep one session's confirmation lifecycle in a single scenario."
)]
async fn ceremonies_require_browser_binding_and_confirmation_belongs_to_one_session() {
    let mut fixture = Fixture::new().await;
    let (started, _) = fixture
        .start(
            "/webauthn/authenticate/start",
            "",
            json!({"handle":fixture.username}),
        )
        .await;
    let assertion = fixture.assertion(&started);
    let body = json!({"ceremony_id":started["ceremony_id"],"credential":assertion});
    for cookies in [
        String::new(),
        format!(
            "{}={}",
            BrowserCookie::Ceremony.as_str(),
            Secret::generate().expect("browser secret").encoded()
        ),
    ] {
        let response = fixture
            .request(
                "/webauthn/authenticate/finish",
                Method::POST,
                &cookies,
                body.clone(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }
    // A passkey sign-in confirms its session, so enrollment right after it prompts once.
    let signed_in = fixture.login().await;
    fixture
        .start("/account/passkeys/enroll/start", &signed_in, json!({}))
        .await;
    // Another session of the same account, from social sign-in, is not confirmed.
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    let secret = security::Session::create(
        &mut tx,
        security::RequestContext::TEST,
        fixture.user_id,
        AuthenticationMethod::Federation.into(),
    )
    .await
    .expect("social session");
    tx.commit().await.expect("commit");
    let social = format!("{}={}", BrowserCookie::Session.as_str(), secret.encoded());
    let session_id = fixture
        .app
        .database
        .sessions()
        .find_active_by_browser_secret(secret.digest().as_bytes())
        .await
        .expect("lookup")
        .expect("session")
        .id;
    let path = format!("/account/passkeys/{}", fixture.key_id);
    for (path, method) in [
        ("/account/passkeys/enroll/start", Method::POST),
        (path.as_str(), Method::DELETE),
    ] {
        security::tests::assert_step_up_required(
            fixture.request(path, method, &social, json!({})).await,
        )
        .await;
    }
    let response = fixture
        .request(
            &path,
            Method::PATCH,
            &social,
            json!({"friendly_name":"Renamed"}),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "renaming needs no confirmation"
    );
    // A confirmation proves possession for the session that started it only.
    let (started, browser) = fixture
        .start("/account/passkeys/confirm/start", &social, json!({}))
        .await;
    let assertion = fixture.assertion(&started);
    let response = fixture
        .request(
            "/account/passkeys/confirm/finish",
            Method::POST,
            &format!("{signed_in}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "confirmation is bound to the initiating session"
    );
    let (started, browser) = fixture
        .start("/account/passkeys/confirm/start", &social, json!({}))
        .await;
    let assertion = fixture.assertion(&started);
    let response = fixture
        .request(
            "/account/passkeys/confirm/finish",
            Method::POST,
            &format!("{social}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // The confirmation replaces the cookie, so a copy of the old one gains nothing.
    let stale = social;
    let social = Fixture::cookie(&response);
    assert!(fixture.session(&stale).await.is_none());
    assert_eq!(
        fixture.session(&social).await.expect("same session").id,
        session_id
    );
    assert_eq!(
        fixture.events().await.first(),
        Some(&DomainEvent::PasskeyConfirmed { session_id })
    );
    let confirming = fixture.app.database.sessions().passkey(session_id).await;
    assert_eq!(confirming.expect("passkey"), Some(fixture.key_id));
    let confirmed_at = || async {
        fixture
            .app
            .database
            .sessions()
            .find_active_by_id(session_id)
            .await
            .expect("lookup")
            .expect("session")
            .passkey_confirmed_at
            .expect("confirmed")
    };
    let confirmed = confirmed_at().await;
    // Confirmed actions do not extend the confirmation.
    let (started, browser) = fixture
        .start("/account/passkeys/enroll/start", &social, json!({}))
        .await;
    // The confirmation authorized enrollment at start; its lapsing at the authenticator
    // must not discard the new credential.
    fixture
        .app
        .database
        .sessions()
        .confirm_passkey(
            session_id,
            PasskeyId::new(),
            confirmed - chrono::Duration::hours(1),
        )
        .await
        .expect("stale confirmation");
    let credential = fixture.credential(&started);
    let response = fixture
        .request(
            "/account/passkeys/enroll/finish",
            Method::POST,
            &format!("{social}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"friendly_name":"Second","credential":credential}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    fixture
        .app
        .database
        .sessions()
        .confirm_passkey(session_id, PasskeyId::new(), confirmed)
        .await
        .expect("restore confirmation");
    // Removal revokes both other sessions, the passkey sign-in and this one.
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    security::Session::create(
        &mut tx,
        security::RequestContext::TEST,
        fixture.user_id,
        AuthenticationMethod::Federation.into(),
    )
    .await
    .expect("third session");
    tx.commit().await.expect("commit");
    let response = fixture
        .request(&path, Method::DELETE, &social, json!({}))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(confirmed_at().await, confirmed);
    let events = fixture.events().await;
    let removed = events
        .iter()
        .position(|event| {
            *event
                == DomainEvent::PasskeyRemoved {
                    passkey_id: fixture.key_id,
                }
        })
        .expect("removal recorded");
    let mut revoked: Vec<_> = events[..removed]
        .iter()
        .map(|event| match event {
            DomainEvent::SessionRevoked {
                session_id,
                reason: RevocationReason::CredentialRemoved,
            } => *session_id,
            event => panic!("unexpected {event:?}"),
        })
        .collect();
    revoked.dedup();
    assert_eq!(revoked.len(), 2, "one revocation per other session");
    assert!(!revoked.contains(&session_id), "the acting session stays");
    let keys = fixture
        .app
        .database
        .passkeys()
        .list_active(fixture.user_id)
        .await
        .expect("keys");
    assert_eq!(keys.len(), 1);
    let response = fixture
        .request(
            &format!("/account/passkeys/{}", keys[0].id),
            Method::DELETE,
            &social,
            json!({}),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "last passkey cannot be removed"
    );
    assert!(
        fixture.session(&signed_in).await.is_none(),
        "removing a passkey revokes other sessions"
    );
}

/// Signing in with a passkey in a browser holding a social session of the same
/// account confirms that session, keeping its ID but replacing its cookie. A
/// session records the passkey that signed it in, or confirmed it since; a social
/// one names none.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn passkey_sign_in_confirms_the_browsers_session() {
    let mut fixture = Fixture::new().await;
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    let secret = security::Session::create(
        &mut tx,
        security::RequestContext::TEST,
        fixture.user_id,
        AuthenticationMethod::Federation.into(),
    )
    .await
    .expect("social session");
    tx.commit().await.expect("commit");
    let social = format!("{}={}", BrowserCookie::Session.as_str(), secret.encoded());
    let before = fixture.session(&social).await.expect("social session");
    assert_eq!(
        SessionAuthentication::from(&before).acr,
        Acr::Social,
        "social sign-in is not phishing-resistant"
    );
    let cookie = fixture.login_from(&social).await;
    assert!(fixture.session(&social).await.is_none(), "old cookie ends");
    let after = fixture.session(&cookie).await.expect("same session");
    assert_eq!(after.id, before.id);
    let authentication = SessionAuthentication::from(&after);
    assert_eq!(authentication.acr, Acr::PhishingResistant);
    assert_eq!(
        authentication.amr,
        [Amr::Pop, Amr::Mfa, Amr::User, Amr::Fed],
        "both methods are reported"
    );
    assert!(authentication.auth_time > before.authenticated_at);

    let database = fixture.app.database.clone();
    let passkey = async |session| {
        let mut sessions = database.sessions();
        sessions.passkey(session).await.expect("passkey")
    };
    assert_eq!(
        passkey(before.id).await,
        Some(fixture.key_id),
        "confirmed by it"
    );
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    let other = security::Session::create(
        &mut tx,
        security::RequestContext::TEST,
        fixture.user_id,
        AuthenticationMethod::Federation.into(),
    )
    .await
    .expect("another social session");
    tx.commit().await.expect("commit");
    let other = format!("{}={}", BrowserCookie::Session.as_str(), other.encoded());
    let other = fixture.session(&other).await.expect("social session").id;
    assert_eq!(passkey(other).await, None, "a social sign-in names none");
    let fresh = fixture.login().await;
    let fresh = fixture.session(&fresh).await.expect("new session").id;
    assert_eq!(
        passkey(fresh).await,
        Some(fixture.key_id),
        "signed in by it"
    );

    // With two passkeys, the asserting one is recorded: signing in with the
    // newer one, and confirming with it a session the older one signed in.
    let newer = fixture.switch_passkey("Newer key").await;
    let signed_in = fixture.login().await;
    let signed_in = fixture.session(&signed_in).await.expect("new session").id;
    assert_eq!(passkey(signed_in).await, Some(newer), "signed in by it");
    let (started, browser) = fixture
        .start("/account/passkeys/confirm/start", &cookie, json!({}))
        .await;
    let assertion = fixture.assertion(&started);
    let response = fixture
        .request(
            "/account/passkeys/confirm/finish",
            Method::POST,
            &format!("{cookie}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(passkey(before.id).await, Some(newer), "confirmed by it");
}

/// A sign-in started on one replica finishes on the other, and signing out on one
/// ends the session on both.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sign_in_and_logout_span_replicas() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    let username = json!({"handle":fixture.username});
    let (started, browser) = fixture
        .on(&replicas.a)
        .start("/webauthn/authenticate/start", "", username)
        .await;
    let assertion = fixture.assertion(&started);
    let finished = fixture
        .on(&replicas.b)
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(finished.status(), StatusCode::NO_CONTENT);
    let session = Fixture::cookie(&finished);
    fixture.on(&replicas.a);
    let read = fixture.request(routes::passkey::LIST, Method::GET, &session, json!({}));
    assert_eq!(read.await.status(), StatusCode::OK);
    let browser = Browser {
        cookie: session.clone(),
        ..Browser::signed_out()
    };
    let logout = browser
        .submit(&replicas.a, routes::page::LOGOUT, &[], OWN_PAGE)
        .await;
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    fixture.on(&replicas.b);
    let read = fixture.request(routes::passkey::LIST, Method::GET, &session, json!({}));
    assert_eq!(read.await.status(), StatusCode::UNAUTHORIZED);
}

impl Fixture {
    /// Signs in with the passkey, and returns the session cookie pair and every
    /// secret the ceremony carried: its cookie and ID, the challenge and signature.
    async fn login_with_secrets(&mut self) -> (String, Vec<String>) {
        let username = json!({"handle": self.username});
        let (started, browser) = self
            .start("/webauthn/authenticate/start", "", username)
            .await;
        let assertion = self.assertion(&started);
        let signature =
            serde_json::to_value(&assertion).expect("assertion")["response"]["signature"]
                .as_str()
                .expect("signature")
                .to_owned();
        let finished = self
            .request(
                "/webauthn/authenticate/finish",
                Method::POST,
                &browser,
                json!({"ceremony_id": started["ceremony_id"], "credential": assertion}),
            )
            .await;
        assert_eq!(finished.status(), StatusCode::NO_CONTENT);
        let session = Self::cookie(&finished);
        let cookie = |pair: &str| pair.split_once('=').expect("cookie pair").1.to_owned();
        let secrets = vec![
            cookie(&session),
            cookie(&browser),
            started["ceremony_id"]
                .as_str()
                .expect("ceremony")
                .to_owned(),
            started["public_key"]["publicKey"]["challenge"]
                .as_str()
                .expect("challenge")
                .to_owned(),
            signature,
        ];
        (session, secrets)
    }

    /// Authorizes the trusted `client` for the browser holding `session`, exchanges
    /// the code, and returns every secret the flow carried: the authorization
    /// query's state, nonce and PKCE challenge, the code, its verifier and the tokens.
    async fn exchange_with_secrets(
        &self,
        session: &str,
        client: &piquel_common::clients::ClientRegistration,
    ) -> Vec<String> {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let challenge = piquel_crypto::Pkce::challenge(verifier).expect("PKCE");
        let mut authorize = Url::parse(&format!("{AUTH_ORIGIN}/oauth/authorize")).expect("URL");
        authorize.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", client.id.as_str()),
            ("redirect_uri", client.redirect_uris[0].as_str()),
            ("scope", "openid offline_access"),
            ("state", "state-in-the-query"),
            ("nonce", "nonce-in-the-query"),
            ("code_challenge_method", "S256"),
            ("code_challenge", &challenge),
        ]);
        let send = |request: Request<Body>| self.router.clone().oneshot(request);
        let authorized = send(
            Request::builder()
                .uri(format!(
                    "{}?{}",
                    authorize.path(),
                    authorize.query().expect("query")
                ))
                .header(header::COOKIE, session)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
        let redirect = Url::parse(
            authorized.headers()[header::LOCATION]
                .to_str()
                .expect("location"),
        )
        .expect("redirect");
        let code = redirect
            .query_pairs()
            .find(|(name, _)| name == "code")
            .expect("code")
            .1
            .into_owned();
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", client.id.as_str()),
                ("redirect_uri", client.redirect_uris[0].as_str()),
                ("code", &code),
                ("code_verifier", verifier),
            ])
            .finish();
        let exchanged = send(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(exchanged.status(), StatusCode::OK);
        let tokens = Self::json(exchanged).await;
        let mut secrets = vec![
            "state-in-the-query".to_owned(),
            "nonce-in-the-query".to_owned(),
            challenge,
            code,
            verifier.to_owned(),
        ];
        for token in ["access_token", "id_token", "refresh_token"] {
            secrets.push(tokens[token].as_str().expect("token").to_owned());
        }
        secrets
    }
}

/// A passkey sign-in, then an authorization code exchanged for tokens, through
/// replicas of the whole service, export no secret: no cookie, ceremony, `WebAuthn`
/// challenge or assertion, authorization query, code, PKCE verifier or token. Each
/// request is one trace holding its queries, and the events it records are logged
/// in it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn telemetry_exports_no_secret_of_a_sign_in_and_code_exchange() {
    use piquel_telemetry::Telemetry;

    let capture = Telemetry::capture(crate::TELEMETRY_FILTER);
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    let client = piquel_common::clients::ClientRegistration {
        trusted: true,
        ..crate::tests::registration(
            piquel_common::clients::ClientKind::Public,
            "https://client.example",
        )
    };
    crate::tests::register(&fixture.app.database, &client)
        .await
        .expect("client");
    let (session, mut secrets) = fixture.on(&replicas.a).login_with_secrets().await;
    secrets.extend(
        fixture
            .on(&replicas.b)
            .exchange_with_secrets(&session, &client)
            .await,
    );
    let exported = capture.exported_text();
    for secret in &secrets {
        assert!(
            exported.iter().all(|text| !text.contains(secret.as_str())),
            "telemetry exported {secret}"
        );
    }

    let spans = capture.spans();
    let exchange = spans
        .iter()
        .find(|span| span.name == "POST /oauth/token")
        .expect("token request span");
    let trace = exchange.span_context.trace_id();
    assert!(
        spans.iter().any(|span| {
            span.span_context.trace_id() == trace
                && span
                    .attributes
                    .iter()
                    .any(|attribute| attribute.key.as_str() == "db.query.text")
        }),
        "the exchange's queries are spans of its trace"
    );
    let logged = capture
        .logs()
        .into_iter()
        .find(|log| {
            log.attributes_iter().any(|(key, value)| {
                key.as_str() == "event.kind" && format!("{value:?}").contains("grant_issued")
            })
        })
        .expect("the issued grant is logged");
    assert_eq!(
        logged.trace_context().map(|context| context.trace_id),
        Some(trace),
        "the event's log line links to the exchange's trace"
    );
}

/// A passkey proof of a handoff to the admin dashboard counts for that handoff
/// only: its ceremony is bound to the browser and session that started it, is
/// used once, and leaves the session's own confirmation as it was. A ceremony
/// confirming the session is no proof of a handoff.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_admin_proof_counts_for_its_handoff_only() {
    let mut fixture = Fixture::new().await;
    let cookie = fixture.login().await;
    let session = fixture.session(&cookie).await.expect("session");
    let headers = |cookies: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookies.parse().expect("cookies"));
        headers
    };
    let owner = AccountService::new(fixture.database().clone())
        .owner(RequestContext::TEST, &headers(&cookie))
        .await
        .expect("lookup")
        .expect("signed in");
    let prove = async |fixture: &mut Fixture, start: &str| {
        let (started, browser) = fixture.start(start, &cookie, json!({})).await;
        let credential = fixture.assertion(&started);
        let assertion = json!({"ceremony_id": started["ceremony_id"], "credential": credential});
        (assertion.to_string(), format!("{cookie}; {browser}"))
    };

    let (confirmation, browser) = prove(&mut fixture, routes::passkey::CONFIRM_START).await;
    let refused = fixture
        .app
        .verify_admin_proof(&headers(&browser), &owner, &confirmation)
        .await;
    assert!(refused.is_err(), "a confirmation of the session");

    let (assertion, browser) = prove(&mut fixture, routes::passkey::ADMIN_PROOF_START).await;
    let refused = fixture
        .app
        .verify_admin_proof(&headers(&cookie), &owner, &assertion)
        .await;
    assert!(refused.is_err(), "another browser");
    let proof = fixture
        .app
        .verify_admin_proof(&headers(&browser), &owner, &assertion)
        .await
        .expect("proved");
    assert_eq!(proof.session_id(), session.id);
    let after = fixture.session(&cookie).await.expect("session");
    assert_eq!(
        after.passkey_confirmed_at, session.passkey_confirmed_at,
        "the session's own confirmation is as it was"
    );
    let replayed = fixture
        .app
        .verify_admin_proof(&headers(&browser), &owner, &assertion)
        .await;
    assert!(replayed.is_err(), "once only");
}

/// A passkey sign-in to an account scheduled for deletion gets no session, but an
/// offer, in its own cookie, which the sign-in page restores the account with once,
/// signing in with that passkey, on any replica. A disabled account gets neither.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signing_in_to_an_account_scheduled_for_deletion_offers_to_restore_it() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    tx.users()
        .set_status(fixture.user_id, AccountStatus::Deleting)
        .await
        .expect("status");
    tx.deletions()
        .schedule(
            fixture.user_id,
            chrono::Utc::now() + chrono::Duration::days(30),
        )
        .await
        .expect("schedule");
    tx.commit().await.expect("commit");

    let username = json!({"username": fixture.username});
    let (started, browser) = fixture
        .on(&replicas.a)
        .start("/webauthn/authenticate/start", "", username.clone())
        .await;
    let assertion = fixture.assertion(&started);
    let offered = fixture
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            json!({"ceremony_id": started["ceremony_id"], "credential": assertion}),
        )
        .await;
    assert_eq!(offered.status(), StatusCode::NO_CONTENT);
    let offer = Fixture::cookie(&offered);
    assert!(
        offer.starts_with(BrowserCookie::Restore.as_str()),
        "an offer, and no session: {offer}"
    );

    let holder = Browser {
        cookie: offer,
        ..Browser::signed_out()
    };
    let restore = [("action", "restore")];
    let restored = holder
        .submit(&replicas.b, routes::page::LOGIN, &restore, OWN_PAGE)
        .await;
    assert_eq!(restored.status(), StatusCode::SEE_OTHER);
    let session = restored
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|cookie| cookie.to_str().ok())
        .find(|cookie| cookie.starts_with(BrowserCookie::Session.as_str()))
        .and_then(|cookie| cookie.split(';').next())
        .expect("signed in")
        .to_owned();
    let session = fixture.session(&session).await.expect("session");
    assert_eq!(session.user_id, fixture.user_id);
    assert_eq!(
        fixture
            .app
            .database
            .sessions()
            .passkey(session.id)
            .await
            .expect("passkey"),
        Some(fixture.key_id)
    );
    assert_eq!(fixture.events().await[1], DomainEvent::AccountRestored {});
    let again = holder
        .submit(&replicas.a, routes::page::LOGIN, &restore, OWN_PAGE)
        .await;
    assert_eq!(
        again.status(),
        StatusCode::BAD_REQUEST,
        "an offer restores once"
    );

    // Disabled after the ceremony started, which still names the passkey.
    let (started, browser) = fixture
        .start("/webauthn/authenticate/start", "", username)
        .await;
    fixture
        .app
        .database
        .users()
        .set_status(fixture.user_id, AccountStatus::Disabled)
        .await
        .expect("disable");
    let assertion = fixture.assertion(&started);
    let refused = fixture
        .request(
            "/webauthn/authenticate/finish",
            Method::POST,
            &browser,
            json!({"ceremony_id": started["ceremony_id"], "credential": assertion}),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
}

/// PKCE verifier of the pushed requests related pages complete.
const PAGE_VERIFIER: &str = "related-page-verifier-0123456789-abcdefghijklmnop";

/// A trusted client whose page, on its approved origin, signs the fixture's account in.
struct RelatedPage {
    /// The page's client.
    client: piquel_common::clients::ClientRegistration,
    /// The page's approved origin.
    origin: RelatedOrigin,
}

impl RelatedPage {
    /// Registers a trusted public client on a fresh subdomain of auth's own domain,
    /// which counts only as `piquel`, as every such origin does, and approves its origin.
    async fn approved(database: &Database) -> Self {
        let origin: RelatedOrigin = format!("https://{}.auth.piquel.fr", TokenId::new())
            .parse()
            .expect("origin");
        let client = piquel_common::clients::ClientRegistration {
            trusted: true,
            ..crate::tests::registration(
                piquel_common::clients::ClientKind::Public,
                origin.as_str(),
            )
        };
        register(database, &client).await.expect("client");
        change(database, async |registry| {
            registry
                .approve_origin(&client.id, &origin, "auth.piquel.fr")
                .await
        })
        .await
        .expect("approved origin");
        Self { client, origin }
    }
}

impl Fixture {
    /// Pushes `page`'s authorization request, with `extra` parameters, and returns
    /// its `request_uri`.
    async fn push(&self, page: &RelatedPage, extra: &[(&str, &str)]) -> String {
        let challenge = piquel_crypto::Pkce::challenge(PAGE_VERIFIER).expect("PKCE");
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", page.client.id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", page.client.redirect_uris[0].as_str()),
                ("scope", "openid"),
                ("state", "page-state"),
                ("code_challenge_method", "S256"),
                ("code_challenge", &challenge),
            ])
            .extend_pairs(extra.iter().copied())
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri(routes::oidc::PAR)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        let response = self.send(request, form).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        Self::json(response).await["request_uri"]
            .as_str()
            .expect("request_uri")
            .to_owned()
    }
    /// Posts JSON from a page on `origin`, which sends no cookies.
    async fn post_from(&self, origin: &str, path: &str, body: Value) -> Response {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json");
        self.send(request, body.to_string()).await
    }
    /// Starts `page`'s sign-in for `request_uri`.
    async fn start_related(&self, page: &RelatedPage, request_uri: &str) -> Response {
        self.post_from(
            page.origin.as_str(),
            routes::passkey::RELATED_START,
            json!({"request_uri":request_uri}),
        )
        .await
    }
    /// Signs `page`'s started sign-in for its own origin and finishes it from there.
    async fn finish_related(&mut self, page: &RelatedPage, started: &Value) -> Response {
        let assertion = self.assertion_for(page.origin.url().clone(), started);
        self.post_from(
            page.origin.as_str(),
            routes::passkey::RELATED_FINISH,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await
    }
    /// Redeems `code` for `page`'s client with `verifier`.
    async fn redeem(&self, page: &RelatedPage, code: &str, verifier: &str) -> Response {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", page.client.id.as_str()),
                ("redirect_uri", page.client.redirect_uris[0].as_str()),
                ("code", code),
                ("code_verifier", verifier),
            ])
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri(routes::oidc::TOKEN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.send(request, form).await
    }
    /// Lists the origins `/.well-known/webauthn` publishes.
    async fn related_origins(&self) -> Vec<String> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(routes::passkey::RELATED_ORIGINS);
        let response = self.send(request, String::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=300, no-transform"
        );
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        serde_json::from_value(Self::json(response).await["origins"].take()).expect("origins")
    }
}

/// A page on an approved origin signs its account in without a cookie, and gets a
/// code that only its PKCE verifier redeems, once. The sign-in creates a session
/// recorded with the page's client and origin.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn related_pages_sign_in_for_pkce_bound_codes() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(&fixture.app.database).await;
    assert!(
        fixture
            .related_origins()
            .await
            .contains(&page.origin.to_string())
    );
    let mut codes = Vec::new();
    for _ in 0..2 {
        let request_uri = fixture.push(&page, &[]).await;
        let started = fixture.start_related(&page, &request_uri).await;
        assert_eq!(started.status(), StatusCode::OK);
        let headers = started.headers().clone();
        assert_eq!(
            headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            page.origin.as_str()
        );
        assert!(
            headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "pages sign in without cookies"
        );
        assert!(headers.get(header::SET_COOKIE).is_none());
        let started = Fixture::json(started).await;
        // Signed on one replica, finished on the other.
        let finished = fixture
            .on(&replicas.b)
            .finish_related(&page, &started)
            .await;
        assert_eq!(finished.status(), StatusCode::OK);
        assert!(finished.headers().get(header::SET_COOKIE).is_none());
        let answer = Fixture::json(finished).await;
        assert_eq!(answer["state"], "page-state");
        assert_eq!(answer["iss"], AUTH_ORIGIN);
        codes.push(answer["code"].as_str().expect("code").to_owned());
        // The ceremony and its request are spent.
        let assertion = fixture.assertion_for(page.origin.url().clone(), &started);
        let replay = fixture
            .post_from(
                page.origin.as_str(),
                routes::passkey::RELATED_FINISH,
                json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
            )
            .await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let reused = fixture.start_related(&page, &request_uri).await;
        assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    }
    let wrong = "another-verifier-0123456789-abcdefghijklmnopqrstu";
    let redeemed = fixture.redeem(&page, &codes[0], wrong).await;
    assert_eq!(redeemed.status(), StatusCode::BAD_REQUEST);
    let redeemed = fixture.redeem(&page, &codes[1], PAGE_VERIFIER).await;
    assert_eq!(redeemed.status(), StatusCode::OK);
    let DomainEvent::SignedIn {
        session_id,
        method: AuthenticationMethod::Passkey,
        inline: Some(inline),
    } = fixture
        .events()
        .await
        .into_iter()
        .find(|event| matches!(event, DomainEvent::SignedIn { .. }))
        .expect("sign-in")
    else {
        panic!("an inline passkey sign-in");
    };
    assert_eq!(inline.client_id, page.client.id);
    assert_eq!(inline.origin, page.origin);
    let session = fixture
        .app
        .database
        .sessions()
        .find_active_by_id(session_id)
        .await
        .expect("session lookup")
        .expect("active session");
    assert_eq!(
        SessionAuthentication::from(&session).acr,
        Acr::PhishingResistant
    );
}

/// Sign-in is refused to unapproved origins, for another client's request, from
/// another origin than its start, for an assertion signed for another origin and
/// without user verification. A request needing auth's pages stays usable there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn related_sign_in_refuses_other_origins_requests_and_unverified_users() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(&fixture.app.database).await;
    let other = RelatedPage::approved(&fixture.app.database).await;

    let request_uri = fixture.push(&page, &[]).await;
    let unapproved = fixture
        .post_from(
            "https://unapproved.example",
            routes::passkey::RELATED_START,
            json!({"request_uri":request_uri}),
        )
        .await;
    assert_eq!(unapproved.status(), StatusCode::FORBIDDEN);
    assert!(
        unapproved
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    // Another client's page cannot claim the request, which stays its client's.
    let claimed = fixture.start_related(&other, &request_uri).await;
    assert_eq!(claimed.status(), StatusCode::BAD_REQUEST);
    let started = fixture.start_related(&page, &request_uri).await;
    assert_eq!(started.status(), StatusCode::OK);
    let started = Fixture::json(started).await;
    // The ceremony finishes only on the page that started it.
    let assertion = fixture.assertion_for(other.origin.url().clone(), &started);
    let moved = fixture
        .post_from(
            other.origin.as_str(),
            routes::passkey::RELATED_FINISH,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(moved.status(), StatusCode::FORBIDDEN);

    // The verifier accepts auth's own origin too, but the page must have signed.
    let started = Fixture::json(
        fixture
            .start_related(&page, &fixture.push(&page, &[]).await)
            .await,
    )
    .await;
    let assertion = fixture.assertion(&started);
    let elsewhere = fixture
        .post_from(
            page.origin.as_str(),
            routes::passkey::RELATED_FINISH,
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(elsewhere.status(), StatusCode::BAD_REQUEST);

    let mut started = Fixture::json(
        fixture
            .start_related(&page, &fixture.push(&page, &[]).await)
            .await,
    )
    .await;
    started["public_key"]["publicKey"]["userVerification"] = json!("discouraged");
    let unverified = fixture.finish_related(&page, &started).await;
    assert_eq!(unverified.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        fixture.events().await.first(),
        Some(&DomainEvent::SignInFailed {
            method: AuthenticationMethod::Passkey,
            reason: SignInFailure::InvalidCredential,
        })
    );

    // `prompt=consent` needs the consent page: the request is left for it.
    let request_uri = fixture.push(&page, &[("prompt", "consent")]).await;
    let refused = fixture.start_related(&page, &request_uri).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(Fixture::json(refused).await["code"], "interaction_required");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", page.client.id.as_str()),
            ("request_uri", &request_uri),
        ])
        .finish();
    let redirect = fixture
        .request(
            &format!("{}?{query}", routes::oidc::AUTHORIZE),
            Method::GET,
            "",
            json!({}),
        )
        .await;
    assert_eq!(redirect.status(), StatusCode::SEE_OTHER);

    // A removed origin's pages stop at once.
    change(&fixture.app.database, async |registry| {
        registry.remove_origin(&page.client.id, &page.origin).await
    })
    .await
    .expect("removed");
    assert!(
        !fixture
            .related_origins()
            .await
            .contains(&page.origin.to_string())
    );
    let removed = fixture
        .start_related(&page, &fixture.push(&page, &[]).await)
        .await;
    assert_eq!(removed.status(), StatusCode::FORBIDDEN);
}

/// An account scheduled for deletion signs in on no related page: only auth's
/// sign-in page offers to restore it, so the page is told to send the user there.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_account_being_deleted_signs_in_on_auths_pages_only() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(fixture.database()).await;
    let mut tx = fixture.app.database.begin().await.expect("transaction");
    tx.users()
        .set_status(fixture.user_id, AccountStatus::Deleting)
        .await
        .expect("status");
    tx.deletions()
        .schedule(
            fixture.user_id,
            chrono::Utc::now() + chrono::Duration::days(30),
        )
        .await
        .expect("schedule");
    tx.commit().await.expect("commit");

    let request_uri = fixture.push(&page, &[]).await;
    let started = Fixture::json(fixture.start_related(&page, &request_uri).await).await;
    let refused = fixture.finish_related(&page, &started).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(refused.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(Fixture::json(refused).await["code"], "interaction_required");
}

/// A recovered passkey during its probation signs in on a related page as on
/// auth's, without confirming the session, so a request for `phr` is refused with
/// `interaction_required`, for auth's pages to answer the client. Without that
/// target it signs in.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_passkey_meets_no_phr_on_related_pages() {
    let mut fixture = Fixture::new().await;
    let replicas = Replicas::new().await;
    fixture.on(&replicas.a);
    let page = RelatedPage::approved(fixture.database()).await;
    let recovery = piquel_common::RecoveryId::new();
    let mut recoveries = fixture.database().recoveries();
    recoveries
        .insert(&piquel_repository::InsertRecovery {
            id: recovery,
            user_id: fixture.user_id,
            secret_digest: &recovery.as_uuid().as_bytes().repeat(2),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .expect("recovery");
    let completed = recoveries
        .complete(
            fixture.user_id,
            recovery,
            fixture.key_id,
            crate::recovery::PROBATION,
        )
        .await;
    assert!(completed.expect("complete"));

    let request_uri = fixture.push(&page, &[("acr_values", "phr")]).await;
    let started = Fixture::json(fixture.start_related(&page, &request_uri).await).await;
    let refused = fixture.finish_related(&page, &started).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(Fixture::json(refused).await["code"], "interaction_required");

    let request_uri = fixture.push(&page, &[]).await;
    let started = Fixture::json(fixture.start_related(&page, &request_uri).await).await;
    assert_eq!(
        fixture.finish_related(&page, &started).await.status(),
        StatusCode::OK
    );
}
