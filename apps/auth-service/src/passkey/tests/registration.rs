//! Signup: handle rules, invitations and attaching a pending social signup.

use super::*;
use crate::tests::pending_sign_in;
use sourceorigin_repository::InsertInvitation;

impl Fixture {
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
        &fixture.app.email,
        None,
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

/// With signup open, an invitation's link is still redeemed, once: a mailed one
/// starts the account with its address, verified and primary.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_mailed_invitation_starts_the_account_with_its_address() {
    let fixture = Fixture::new().await;
    let database = fixture.app.database.clone();
    let (id, token) = (TokenId::new(), Secret::generate().expect("token"));
    let address = format!("{id}@example.com");
    database
        .security()
        .create_invitation(&InsertInvitation {
            id,
            secret_digest: token.digest().as_bytes(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            email: Some(&address),
        })
        .await
        .expect("invitation");
    let handle = format!("inv-{}", &id.to_string()[24..]);
    let invited = json!({"handle": handle, "invitation": token.encoded()});
    let response = fixture.register("", invited).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let user = database
        .users()
        .find_active_by_handle(&Handle::parse(&handle).expect("handle"))
        .await
        .expect("user")
        .expect("registered");
    let emails = database.emails().list(user.id).await.expect("emails");
    let [email] = &emails[..] else {
        panic!("one address: {emails:?}");
    };
    assert_eq!(email.normalized_email, address);
    assert!(email.is_primary && email.verified_at.is_some(), "{email:?}");
    let history = database.events().history_for_user(user.id, 100).await;
    let redeemed = DomainEvent::InvitationRedeemed { invitation_id: id };
    assert!(
        history
            .expect("history")
            .iter()
            .any(|stored| stored.event.known() == Some(&redeemed)),
        "recorded"
    );
    let again = json!({"handle": format!("{handle}-2"), "invitation": token.encoded()});
    let response = fixture
        .request("/webauthn/register/start", Method::POST, "", again)
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "used once");
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

/// An account keeps at most 100 active passkeys: enrolling a 101st is refused as
/// it starts, before the authenticator creates a passkey, and the database refuses
/// one that started before the account filled up. Neither stores anything.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn enrollment_refuses_a_101st_passkey() {
    const REFUSED: &str = "This account already has 100 passkeys, the most it can keep. \
        Remove one in your account settings, or ask SourceOrigin support.";
    let mut fixture = Fixture::new().await;
    let signed_in = fixture.login().await;
    let (started, browser) = fixture
        .start("/account/passkeys/enroll/start", &signed_in, json!({}))
        .await;
    // The fixture's passkey is the first of 100.
    for _ in 1..100 {
        fixture
            .database()
            .passkeys()
            .insert(&crate::tests::unusable_passkey(fixture.user_id))
            .await
            .expect("passkey");
    }
    let refused = fixture
        .request(
            "/account/passkeys/enroll/start",
            Method::POST,
            &signed_in,
            json!({}),
        )
        .await;
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(Fixture::json(refused).await["error"], REFUSED);
    let credential = fixture.credential(&started);
    let response = fixture
        .request(
            "/account/passkeys/enroll/finish",
            Method::POST,
            &format!("{signed_in}; {browser}"),
            json!({"ceremony_id":started["ceremony_id"],"friendly_name":"One more","credential":credential}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(Fixture::json(response).await["error"], REFUSED);
    let active = fixture
        .database()
        .passkeys()
        .list_active(fixture.user_id)
        .await
        .expect("passkeys");
    assert_eq!(active.len(), 100);
}
