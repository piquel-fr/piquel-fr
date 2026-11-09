//! Browser binding, session confirmation and admin proofs, from a handoff or the
//! dashboard's own page.

use super::*;
use crate::{config::PasskeyConfig, security::Cached};
use axum::{Json, extract::State};
use sourceorigin_common::{config::Origin, events::RevocationReason};

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
    let owner = AccountService::new(fixture.database().clone())
        .owner(RequestContext::TEST, &cookies(&cookie))
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
        .verify_admin_proof(&cookies(&browser), &owner, &confirmation)
        .await;
    assert!(refused.is_err(), "a confirmation of the session");

    let (assertion, browser) = prove(&mut fixture, routes::passkey::ADMIN_PROOF_START).await;
    let refused = fixture
        .app
        .verify_admin_proof(&cookies(&cookie), &owner, &assertion)
        .await;
    assert!(refused.is_err(), "another browser");
    let proof = fixture
        .app
        .verify_admin_proof(&cookies(&browser), &owner, &assertion)
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
        .verify_admin_proof(&cookies(&browser), &owner, &assertion)
        .await;
    assert!(replayed.is_err(), "once only");
}

/// The admin dashboard confirms on its own page with a passkey signed for its
/// origin, which `/.well-known/webauthn` lists for browsers. That proof counts
/// for the dashboard only: auth's handoff refuses it, and the dashboard refuses
/// one signed for auth's own pages.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_dashboard_proves_with_passkeys_signed_for_its_origin() {
    let mut fixture = Fixture::new().await;
    let cookie = fixture.login().await;
    let session = fixture.session(&cookie).await.expect("session");
    // The software authenticator knows no related origins, so the dashboard is on a
    // subdomain of auth's RP ID, which it signs for.
    let dashboard: Origin = "https://admin.auth.sourceorigin.dev"
        .parse()
        .expect("dashboard origin");
    let app = PasskeyApplication::new(
        fixture.database().clone(),
        &PasskeyConfig {
            origin: AUTH_ORIGIN.parse().expect("origin"),
            invite_required: false,
        },
        &fixture.app.email,
        Some(&dashboard),
        fixture.app.oidc.clone(),
    )
    .expect("passkeys");
    let Cached(_, Json(listed)) = PasskeyApplication::related_origins(State(app.clone()))
        .await
        .expect("related origins");
    assert!(
        listed
            .origins
            .iter()
            .any(|origin| origin.as_str() == "https://admin.auth.sourceorigin.dev")
    );
    let owner = AccountService::new(fixture.database().clone())
        .owner(RequestContext::TEST, &cookies(&cookie))
        .await
        .expect("lookup")
        .expect("signed in");
    let prove = async |fixture: &mut Fixture, origin: &Url| {
        let (started, browser) = fixture
            .start(routes::passkey::ADMIN_PROOF_START, &cookie, json!({}))
            .await;
        let credential = fixture.assertion_for(origin.clone(), &started);
        let assertion = json!({"ceremony_id": started["ceremony_id"], "credential": credential});
        (assertion, cookies(&format!("{cookie}; {browser}")))
    };
    let verify = async |headers: &HeaderMap, assertion: &Value| {
        let input = serde_json::from_value(assertion.clone()).expect("assertion");
        app.verify_dashboard_proof(
            headers,
            RequestContext::TEST,
            session.user_id,
            session.id,
            &input,
        )
        .await
    };

    let auth = fixture.origin.clone();
    let (assertion, browser) = prove(&mut fixture, &auth).await;
    assert!(
        verify(&browser, &assertion).await.is_err(),
        "auth's own origin"
    );

    let (assertion, browser) = prove(&mut fixture, dashboard.as_url()).await;
    let refused = app
        .verify_admin_proof(&browser, &owner, &assertion.to_string())
        .await;
    assert!(refused.is_err(), "a handoff");

    let (assertion, browser) = prove(&mut fixture, dashboard.as_url()).await;
    let proof = verify(&browser, &assertion).await.expect("proved");
    assert_eq!(proof.session_id(), session.id);
}

/// Headers carrying the browser's `cookies`.
fn cookies(cookies: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookies.parse().expect("cookies"));
    headers
}
