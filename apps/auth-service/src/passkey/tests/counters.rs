//! Signature counters: concurrent assertions and lagging copies of a passkey.

use super::*;

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
