//! What a probation passkey can and cannot do, and what nobody may remove meanwhile.

use super::*;
use crate::{account::Subject, security::SessionError};

/// A link signs its browser in with a new session, whatever session the browser
/// had. A probation passkey signing in again renews an unconfirmed session,
/// recording itself and its method without confirming it, and never downgrades a
/// confirmed one.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_passkey_signs_in_anew_and_never_confirms() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let social = Browser::sign_in_with(
        scenario.database(),
        scenario.user(),
        AuthenticationMethod::Federation,
    )
    .await;
    let response = scenario.enroll_from(&token, &social.cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = Fixture::cookie(&response);
    let session = scenario.session(&cookie).await.expect("session");
    assert_ne!(session.id, social.session_id, "a new session");
    let social_session = scenario
        .database()
        .sessions()
        .find_by_id(social.session_id)
        .await;
    let revoked = social_session.expect("lookup").expect("session").revoked_at;
    assert!(revoked.is_some(), "the browser's session is revoked");
    let recovered = scenario.latest().await.passkey_id.expect("its passkey");
    scenario.swap();

    let social = Browser::sign_in_with(
        scenario.database(),
        scenario.user(),
        AuthenticationMethod::Federation,
    )
    .await;
    let response = scenario.login(&social.cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let renewed = Fixture::cookie(&response);
    let session = scenario.session(&renewed).await.expect("session");
    assert_eq!(session.id, social.session_id, "renewed");
    assert_eq!(session.passkey_confirmed_at, None, "not confirmed");
    assert_eq!(
        session.authentication_methods,
        [
            AuthenticationMethod::Federation,
            AuthenticationMethod::Passkey
        ]
    );
    let signed_by = scenario.database().sessions().passkey(session.id).await;
    assert_eq!(signed_by.expect("passkey"), Some(recovered));

    let confirmed = scenario.signed_in_with(scenario.keys.key_id).await;
    let response = scenario.login(&confirmed).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = Fixture::json(response).await;
    assert_eq!(body["code"], "passkey_required");
    let says = body["error"].as_str().expect("message");
    assert!(says.ends_with("Sign out first."), "{says}");
    let session = scenario.session(&confirmed).await.expect("session");
    assert!(session.passkey_confirmed_at.is_some(), "not downgraded");

    // A link used in a browser an older passkey confirmed still signs in anew.
    let token = {
        scenario.swap();
        let undoable = scenario.latest().await.id;
        let (status, ..) = scenario.undo(undoable).await;
        assert_eq!(status, StatusCode::OK);
        scenario.recover().await
    };
    let confirmed = scenario.signed_in_with(scenario.keys.key_id).await;
    let response = scenario.enroll_from(&token, &confirmed).await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "from a confirmed browser"
    );
}

/// While a recovery can be undone, nobody removes a passkey but the recovery's
/// own: not the owner from a session an older passkey confirmed, not support.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn nothing_removes_an_older_passkey_mid_recovery() {
    let mut scenario = Scenario::new().await;
    let older = scenario.keys.key_id;
    let other = scenario.keys.switch_passkey("Other key").await;
    let token = scenario.recover().await;
    let confirmed = scenario.signed_in_with(older).await;

    let response = scenario.remove(&confirmed, other).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "while the link works"
    );
    assert_eq!(code(response).await, "recovery_in_progress");
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let subject = Subject::operator(
        scenario.user(),
        operator(admin, Utc::now()),
        recovery_reason(),
    );
    let service = AccountService::new(scenario.database().clone());
    let refused = service.revoke_passkey(&subject, other).await;
    assert!(
        matches!(
            refused,
            Err(AccountError::Recovery(RecoveryError::InProgress))
        ),
        "support either"
    );

    scenario.enroll(&token).await;
    let recovered = scenario.latest().await.passkey_id.expect("its passkey");
    let response = scenario.remove(&confirmed, older).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "during the probation"
    );
    let response = scenario.remove(&confirmed, recovered).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "its own may go");
}

/// A probation passkey's session never confirms, so it can neither download the
/// account's data nor delete the account: both require a recent passkey
/// confirmation, checked under the account lock. Nor can it restore an account
/// scheduled for deletion meanwhile: signing in offers it nothing, since only a
/// passkey from before the recovery may take back a deletion.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_probation_passkey_neither_exports_deletes_nor_restores_the_account() {
    let mut scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let cookie = scenario.enroll(&token).await;
    let owner = Browser {
        cookie,
        ..Browser::signed_out()
    }
    .owner(scenario.database())
    .await;
    let service = AccountService::new(scenario.database().clone());
    let refused = |result: Result<(), AccountError>| {
        matches!(
            result,
            Err(AccountError::Owner(SessionError::StepUpRequired { .. }))
        )
    };
    assert!(refused(service.export(&owner).await.map(drop)));
    let handle = scenario.keys.username.clone();
    assert!(refused(
        service.delete_account(&owner, &handle).await.map(drop)
    ));
    let account = scenario
        .database()
        .users()
        .find_by_id(scenario.user())
        .await;
    assert_eq!(
        account.expect("lookup").expect("account").status,
        AccountStatus::Active
    );

    scenario
        .admin()
        .schedule_deletion(&cli(), scenario.user(), recovery_reason())
        .await
        .expect("support schedules the deletion");
    scenario.swap();
    let refused = scenario.login("").await;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "offered no restore"
    );
    assert!(
        refused
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|cookie| cookie.to_str().ok())
            .all(|cookie| !cookie.starts_with(BrowserCookie::Restore.as_str())),
        "no offer cookie"
    );
    let account = scenario
        .database()
        .users()
        .find_by_id(scenario.user())
        .await;
    assert_eq!(
        account.expect("lookup").expect("account").status,
        AccountStatus::Deleting
    );
}
