use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request},
};
use piquel_repository::{DatabaseConfig, PendingFederation};
use tower::ServiceExt;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

struct Fixture {
    app: PasskeyApplication,
    authenticator: WebauthnAuthenticator<SoftPasskey>,
    origin: Url,
    user_id: UserId,
    key_id: TokenId,
    username: String,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("isolated test database");
        let database = Database::connect(
            DatabaseConfig::new_development(&url, 5, std::time::Duration::from_secs(5))
                .expect("configuration"),
        )
        .await
        .expect("database");
        database.run_migrations().await.expect("migrations");
        let origin = Url::parse("https://auth.piquel.fr/").expect("origin");
        let app = PasskeyApplication::new(database, "auth.piquel.fr", &origin, false)
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
    async fn start(&self, path: &str, cookies: &str, body: Value) -> (Value, String) {
        let response = self.request(path, Method::POST, cookies, body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = Self::cookie(&response);
        let value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.expect("body"))
                .expect("JSON");
        (value, cookie)
    }
    fn cookie(response: &Response) -> String {
        response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_owned()
    }
    fn assertion(&mut self, started: &Value) -> PublicKeyCredential {
        let challenge = serde_json::from_value(started["public_key"].clone())
            .expect("authentication challenge");
        self.authenticator
            .do_authentication(self.origin.clone(), challenge)
            .expect("software assertion")
    }
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn registration_attaches_a_pending_social_signup_only_when_it_names_it() {
    let fixture = Fixture::new().await;
    let secret = BrowserSecret::new();
    let pending = PendingFederation {
        id: TokenId::new(),
        browser_digest: secret.digest(),
        provider: "github".into(),
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
        BrowserCookie::FederationPending.name(),
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
    assert_eq!(keys[0].credential.pointer("/cred/counter"), Some(&json!(2)));
}

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
        format!("__Host-piquel_ceremony={}", BrowserSecret::new().encoded()),
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
