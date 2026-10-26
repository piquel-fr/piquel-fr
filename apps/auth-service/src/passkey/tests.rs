//! Focused name validation and database-backed `WebAuthn` ceremony invariants.

use super::*;
use crate::{
    account::AccountApplication,
    tests::{AUTH_ORIGIN, Browser, OWN_PAGE, Replicas, pending_sign_in},
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
        let app = PasskeyApplication::new(
            database,
            &PasskeyConfig {
                origin: origin
                    .as_str()
                    .parse::<piquel_common::config::Origin>()
                    .expect("origin"),
                invite_required: false,
                decoy_key: DecoyKey::new(Secret::generate().expect("decoy key")),
            },
        )
        .expect("passkey app");
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
        let (key_id, authenticator) =
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
    ) -> (PasskeyId, WebauthnAuthenticator<SoftPasskey>) {
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
        app.database
            .passkeys()
            .insert(&InsertPasskey {
                id,
                credential_id: key.cred_id().as_ref().to_vec(),
                user_id,
                credential: serde_json::to_value(key).expect("credential"),
                friendly_name: name.into(),
            })
            .await
            .expect("stored key");
        (id, authenticator)
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
        let (id, authenticator) =
            Self::seed_passkey(&self.app, &self.origin, self.user_id, &self.username, name).await;
        self.authenticator = authenticator;
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
        self.router
            .clone()
            .oneshot(
                Request::builder()
                    .extension(crate::security::RequestContext::TEST)
                    .method(method)
                    .uri(path)
                    .header(header::ORIGIN, AUTH_ORIGIN)
                    .header("x-piquel-csrf", "1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookies)
                    .body(Body::from(body.to_string()))
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
        let challenge = serde_json::from_value(started["public_key"].clone())
            .expect("authentication challenge");
        self.authenticator
            .do_authentication(self.origin.clone(), challenge)
            .expect("software assertion")
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
                json!({"username":self.username}),
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

/// Signup normalizes the handle, and refuses invalid and reserved ones with their codes.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signup_applies_the_handle_rules() {
    let fixture = Fixture::new().await;
    for (handle, code) in [("a_b", "handle_invalid"), ("adm1n", "handle_reserved")] {
        let response = fixture
            .request(
                "/webauthn/register/start",
                Method::POST,
                "",
                json!({"username": handle}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{handle}");
        assert_eq!(Fixture::json(response).await["code"], code, "{handle}");
    }
    let (started, _) = fixture
        .start(
            "/webauthn/register/start",
            "",
            json!({"username": " New-User "}),
        )
        .await;
    assert_eq!(
        started["public_key"]["publicKey"]["user"]["name"],
        "new-user"
    );
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
            json!({"username":"unrelated","pending_signup":TokenId::new()}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    for (explicit, attached) in [(None, false), (Some(pending.id), true)] {
        let username = format!("reg-{}", &TokenId::new().to_string()[24..]);
        let response = fixture
            .register(
                &social,
                json!({"username":username,"pending_signup":explicit}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let user = database
            .users()
            .find_active_by_username(&username)
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
            json!({"username":fixture.username}),
        )
        .await;
    let (newer, _) = fixture
        .start(
            "/webauthn/authenticate/start",
            &browser,
            json!({"username":fixture.username}),
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
            json!({"username":fixture.username}),
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
            json!({"username":fixture.username}),
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

/// Checks that a username without an account gets a stable challenge shaped like a
/// real account's, and that finishing it fails exactly like an unregistered passkey.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn unknown_usernames_get_stable_decoys_that_fail_like_unregistered_passkeys() {
    let fixture = Fixture::new().await;
    let unknown = format!("none_{}", &TokenId::new().to_string()[24..]);
    let start = |username: &str| {
        fixture.start(
            "/webauthn/authenticate/start",
            "",
            json!({"username":username}),
        )
    };
    let (known, known_browser) = start(&fixture.username).await;
    let (decoy, decoy_browser) = start(&unknown).await;
    // Apart from the fresh challenge and the credential list, the options are identical.
    let options = |started: &Value| {
        let mut options = started["public_key"].clone();
        options["publicKey"]["challenge"].take();
        options["publicKey"]["allowCredentials"].take();
        options
    };
    assert_eq!(options(&known), options(&decoy));
    let credentials = |started: &Value| {
        started["public_key"]["publicKey"]["allowCredentials"]
            .as_array()
            .expect("allowCredentials")
            .clone()
    };
    let real = &credentials(&known)[0];
    let fields = |value: &Value| -> Vec<String> {
        value
            .as_object()
            .expect("descriptor")
            .keys()
            .cloned()
            .collect()
    };
    for credential in credentials(&decoy) {
        assert_eq!(fields(&credential), fields(real));
        assert_eq!(credential["type"], real["type"]);
    }
    assert_eq!(credentials(&decoy), credentials(&start(&unknown).await.0));
    assert_ne!(
        credentials(&decoy),
        credentials(&start(&format!("{unknown}x")).await.0)
    );

    // A passkey the server never registered, standing in for any guess at the account.
    let (challenge, _) = fixture
        .app
        .webauthn
        .start_passkey_registration(UserId::new().as_uuid(), "stranger", "Stranger", None)
        .expect("registration");
    let mut stranger = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let id = stranger
        .do_registration(fixture.origin.clone(), challenge)
        .expect("software registration")
        .raw_id;
    let mut failures = Vec::new();
    for (started, browser) in [(known, known_browser), (decoy, decoy_browser)] {
        let mut challenge: RequestChallengeResponse =
            serde_json::from_value(started["public_key"].clone()).expect("challenge");
        challenge.public_key.allow_credentials = vec![webauthn_rs_proto::AllowCredentials {
            type_: "public-key".into(),
            id: id.clone(),
            transports: None,
        }];
        let assertion = stranger
            .do_authentication(fixture.origin.clone(), challenge)
            .expect("software assertion");
        let response = fixture
            .request(
                "/webauthn/authenticate/finish",
                Method::POST,
                &browser,
                json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
            )
            .await;
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        failures.push((response.status(), Fixture::json(response).await));
    }
    assert_eq!(failures[0].0, StatusCode::BAD_REQUEST);
    assert_eq!(failures[0], failures[1]);
    assert_eq!(
        fixture.events().await,
        [DomainEvent::SignInFailed {
            method: AuthenticationMethod::Passkey,
            reason: SignInFailure::InvalidCredential,
        }],
        "the decoy's failure concerns no account"
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
    let username = json!({"username":fixture.username});
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
        let username = json!({"username": self.username});
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
