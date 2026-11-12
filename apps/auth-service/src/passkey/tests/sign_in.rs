//! Passkey sign-in on auth's own pages: handles, sessions, replicas and accounts
//! scheduled for deletion.

use super::*;
use crate::tests::OWN_PAGE;
use sourceorigin_common::protocol::claims::Amr;

/// Handles are public, so handle sign-in refuses a handle without an active
/// account, and text that is no handle, before starting any ceremony.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn handle_sign_in_refuses_a_handle_without_an_account_at_once() {
    let fixture = Fixture::new().await;
    for handle in [
        format!("none-{}", &TokenId::new().to_string()[24..]),
        "@not a handle".to_owned(),
    ] {
        let response = fixture
            .request(
                routes::passkey::AUTHENTICATE_START,
                Method::POST,
                "",
                json!({ "handle": handle }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{handle}");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(
            Fixture::json(response).await["error"],
            "No active account has this handle."
        );
    }
}

/// Handle sign-in lists none of the account's credentials, whose IDs would link
/// the account across renames. The authenticator names the account instead, and
/// a passkey of another account is refused, as a failed sign-in of the named one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn handle_sign_in_lists_no_credentials_and_refuses_another_accounts_passkey() {
    let mut fixture = Fixture::new().await;
    let mut other = Fixture::new().await;
    let (started, browser) = fixture
        .start(
            routes::passkey::AUTHENTICATE_START,
            "",
            json!({ "handle": fixture.username }),
        )
        .await;
    let allowed = &started["public_key"]["publicKey"]["allowCredentials"];
    assert!(allowed.as_array().is_none_or(Vec::is_empty), "{allowed}");
    let response = fixture
        .request(
            routes::passkey::AUTHENTICATE_FINISH,
            Method::POST,
            &browser,
            json!({"ceremony_id": started["ceremony_id"], "credential": other.assertion(&started)}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        fixture.events().await.first(),
        Some(&DomainEvent::SignInFailed {
            method: AuthenticationMethod::Passkey,
            reason: SignInFailure::InvalidCredential,
        })
    );
    fixture.login().await;
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
