//! Focused name validation and database-backed `WebAuthn` ceremony invariants.

use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
};
use chrono::{Duration, Utc};
use piquel_crypto::Secret;
use piquel_repository::{DatabaseConfig, PendingFederation};
use serde_json::json;
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

/// Maximum JSON response accepted by the software browser fixture.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Checks the precise signup alphabet and both username length boundaries.
#[test]
fn usernames_preserve_the_existing_ascii_contract() {
    for valid in ["abc".to_owned(), "a_0-b".to_owned(), "a".repeat(32)] {
        assert_eq!(
            Username::parse(valid.clone()).expect("username").as_str(),
            valid
        );
    }
    for invalid in [
        String::new(),
        "ab".into(),
        "a".repeat(33),
        "Uppercase".into(),
        "café".into(),
        "abc def".into(),
        "abc\n".into(),
    ] {
        assert!(matches!(
            Username::parse(invalid),
            Err(PasskeyError::InvalidUsername)
        ));
    }
}

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
    let session_id = piquel_auth_protocol::SessionId::new();
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
    assert!(ManagementCeremony::extract(stored()).is_none());

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

/// Isolated account and counter-capable software authenticator for database scenarios.
struct Fixture {
    /// Routes and persistence under test.
    app: PasskeyApplication,
    /// Software credential capable of user verification and monotonic counters.
    authenticator: WebauthnAuthenticator<SoftPasskey>,
    /// HTTPS origin passed to the authenticator.
    origin: Url,
    /// Seeded account owning the software credential.
    user_id: UserId,
    /// Seeded passkey row used for rename and last-key removal checks.
    key_id: TokenId,
    /// Unique seeded username for identified authentication.
    username: String,
}
impl Fixture {
    /// Seeds an account and passkey in the explicitly configured isolated database.
    async fn new() -> Self {
        let url = piquel_common::Variable::new("TEST_DATABASE_URL")
            .required()
            .expect("isolated test database");
        let database = Database::connect(
            DatabaseConfig::new(&url, 5, std::time::Duration::from_secs(5)).expect("configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let origin = Url::parse("https://auth.piquel.fr/").expect("origin");
        let app = PasskeyApplication::new(
            database,
            &PasskeyConfig {
                origin: origin
                    .as_str()
                    .parse::<piquel_common::Origin>()
                    .expect("origin"),
                invite_required: false,
            },
        )
        .expect("passkey app");
        let user_id = UserId::new();
        let username = format!("key_{}", &TokenId::new().to_string()[24..]);
        let key_id = TokenId::new();
        // This software authenticator supports UV and signed counters, but not
        // resident credentials. Browser tests cover production resident signup;
        // use the library's normal registration to seed this assertion fixture.
        let (challenge, state) = app
            .webauthn
            .start_passkey_registration(user_id.as_uuid(), &username, "Test user", None)
            .expect("registration");
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = authenticator
            .do_registration(origin.clone(), challenge)
            .expect("software registration");
        let key = app
            .webauthn
            .finish_passkey_registration(&registration, &state)
            .expect("verified registration");
        let mut tx = app.database.begin().await.expect("transaction");
        tx.users()
            .insert(&InsertUser {
                id: user_id,
                username: username.clone(),
                display_name: "Test user".into(),
            })
            .await
            .expect("user");
        tx.passkeys()
            .insert(&InsertPasskey {
                id: key_id,
                credential_id: key.cred_id().as_ref().to_vec(),
                user_id,
                credential: serde_json::to_value(key).expect("credential"),
                friendly_name: "Original key".into(),
            })
            .await
            .expect("stored key");
        tx.commit().await.expect("commit");
        Self {
            app,
            authenticator,
            origin,
            user_id,
            key_id,
            username,
        }
    }
    /// Sends a JSON request through the passkey routes with the supplied cookies.
    async fn request(&self, path: &str, method: Method, cookies: &str, body: Value) -> Response {
        self.app
            .clone()
            .routes()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookies)
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response")
    }
    /// Starts a ceremony and returns its challenge JSON and browser-binding cookie.
    async fn start(&self, path: &str, cookies: &str, body: Value) -> (Value, String) {
        let response = self.request(path, Method::POST, cookies, body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = Self::cookie(&response);
        let value = serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                .await
                .expect("body"),
        )
        .expect("JSON");
        (value, cookie)
    }
    /// Extracts the cookie pair from a response for the next simulated browser request.
    fn cookie(response: &Response) -> String {
        response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_owned()
    }
    /// Signs a started authentication challenge using the software credential.
    fn assertion(&mut self, started: &Value) -> PublicKeyCredential {
        let challenge = serde_json::from_value(started["public_key"].clone())
            .expect("authentication challenge");
        self.authenticator
            .do_authentication(self.origin.clone(), challenge)
            .expect("software assertion")
    }
    /// Completes an identified login and returns the new session cookie.
    async fn login(&mut self) -> String {
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
                &browser,
                json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Self::cookie(&response)
    }
    /// Registers a new account with a fresh software credential; returns the finish response.
    async fn register(&self, cookies: &str, body: Value) -> Response {
        let (started, browser) = self.start("/webauthn/register/start", cookies, body).await;
        let challenge =
            serde_json::from_value(started["public_key"].clone()).expect("registration challenge");
        let credential = WebauthnAuthenticator::new(SoftPasskey::new(true))
            .do_registration(self.origin.clone(), challenge)
            .expect("software registration");
        self.request(
            "/webauthn/register/finish",
            Method::POST,
            &format!("{cookies}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":credential}),
        )
        .await
    }
}

/// Checks that abandoned social signup state never attaches to unrelated registration.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn registration_attaches_a_pending_social_signup_only_when_it_names_it() {
    let fixture = Fixture::new().await;
    let secret = Secret::generate().expect("browser secret");
    let pending = PendingFederation {
        id: TokenId::new(),
        browser_digest: secret.digest().as_bytes().to_vec(),
        provider: piquel_auth_protocol::Provider::GitHub,
        issuer: "https://github.com".into(),
        subject: TokenId::new().to_string(),
        email: None,
        display_name: "Abandoned signup".into(),
        return_to: "/".into(),
        link_user_id: None,
        link_session_id: None,
        expires_at: Utc::now() + Duration::minutes(5),
    };
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
        let username = format!("reg_{}", &TokenId::new().to_string()[24..]);
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
    }
}

/// Checks counter ordering under concurrent ceremony snapshots and prevents replay.
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
}

/// Checks browser/session binding, reusable authorization and last-passkey protection.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ceremonies_require_browser_binding_and_management_requires_the_same_session() {
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
    let first = fixture.login().await;
    let second = fixture.login().await;
    let (started, browser) = fixture
        .start("/account/passkeys/authorize/start", &first, json!({}))
        .await;
    let assertion = fixture.assertion(&started);
    let response = fixture
        .request(
            "/account/passkeys/authorize/finish",
            Method::POST,
            &format!("{second}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "management proof is bound to the initiating session"
    );
    let path = format!("/account/passkeys/{}", fixture.key_id);
    let response = fixture
        .request(
            &path,
            Method::PATCH,
            &second,
            json!({"friendly_name":"Unauthorized"}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (started, browser) = fixture
        .start("/account/passkeys/authorize/start", &first, json!({}))
        .await;
    let assertion = fixture.assertion(&started);
    let response = fixture
        .request(
            "/account/passkeys/authorize/finish",
            Method::POST,
            &format!("{first}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"credential":assertion}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    for name in ["Renamed once", "Renamed twice"] {
        let response = fixture
            .request(&path, Method::PATCH, &first, json!({"friendly_name":name}))
            .await;
        assert_eq!(
            response.status(),
            StatusCode::NO_CONTENT,
            "management grant is reusable"
        );
    }
    let response = fixture
        .request(&path, Method::DELETE, &first, json!({}))
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "last passkey cannot be removed"
    );
    let keys = fixture
        .app
        .database
        .passkeys()
        .list_active(fixture.user_id)
        .await
        .expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].friendly_name, "Renamed twice");
}
