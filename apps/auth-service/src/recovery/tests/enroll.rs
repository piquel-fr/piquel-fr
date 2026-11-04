//! What a recovery link enrolls: one passkey, once, signed in without confirming.

use super::*;
use piquel_common::protocol::claims::Acr;
use piquel_repository::SessionAuthentication;

/// Starting a recovery signs the account out everywhere, ends its refresh grants
/// and removes its unverified addresses, so an older verification link stops
/// working. Its link goes to the primary address only. The link enrolls one
/// passkey, once, and signs in with it without confirming the session: no
/// confirmed change accepts it, and confirming with it is refused until the
/// recovery settles. Every verified address hears of it.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_link_enrolls_one_passkey_that_signs_in_without_confirming() {
    let mut scenario = Scenario::new().await;
    let primary = scenario.address("primary", true).await;
    let other = scenario.address("other", false).await;
    let (pending, _) = scenario.unverified("pending").await;
    let before = scenario.signed_in_with(scenario.keys.key_id).await;
    let before_id = scenario.session(&before).await.expect("session").id;
    let client = scenario.consent("https://notes.example").await;
    let family = TokenId::new();
    refresh_grant(
        scenario.database(),
        scenario.user(),
        before_id,
        &client,
        family,
    )
    .await;

    let token = scenario.recover().await;
    assert!(scenario.session(&before).await.is_none(), "signed out");
    let mut tokens = scenario.database().tokens();
    let grants = tokens.revoke_for_user(scenario.user(), None).await;
    assert_eq!(grants.expect("grants"), 0, "already ended");
    let emails = scenario.database().emails().list(scenario.user()).await;
    let emails: Vec<_> = emails
        .expect("emails")
        .iter()
        .map(|email| email.id)
        .collect();
    assert!(!emails.contains(&pending), "the unverified address is gone");
    assert_eq!(
        (scenario.sent(primary).await, scenario.sent(other).await),
        (1, 0),
        "the link goes to the primary address only"
    );
    assert!(scenario.works(&token).await);
    let service = AccountService::new(scenario.database().clone());
    let opened = service.open_recovery(&token).await.expect("open");
    let account = opened.account();
    assert_eq!(
        account.handle.as_str(),
        scenario.keys.username,
        "names the account"
    );

    let cookie = scenario.enroll(&token).await;
    let session = scenario.session(&cookie).await.expect("session");
    assert_eq!(session.passkey_confirmed_at, None, "not confirmed");
    assert_eq!(SessionAuthentication::from(&session).acr, Acr::Social);
    let recovered = scenario.latest().await.passkey_id.expect("its passkey");
    let signed_by = scenario.database().sessions().passkey(session.id).await;
    assert_eq!(signed_by.expect("passkey"), Some(recovered));
    assert_eq!(
        (scenario.sent(primary).await, scenario.sent(other).await),
        (2, 1),
        "every verified address hears of it"
    );
    assert!(!scenario.works(&token).await, "used");

    let response = scenario
        .keys
        .request(
            "/account/passkeys/enroll/start",
            Method::POST,
            &cookie,
            json!({}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(response).await, "step_up_required");
    scenario.swap();
    let response = scenario.confirm(&cookie).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(code(response).await, "recovery_probation");
    let session = scenario.session(&cookie).await.expect("session");
    assert_eq!(session.passkey_confirmed_at, None, "still not confirmed");

    // The probation lasts 15 days: a minute before, still refused; after, it
    // settled.
    let recovery = scenario.latest().await.id;
    let database = scenario.database().clone();
    let almost = Duration::days(15) - Duration::minutes(1);
    database
        .recoveries()
        .backdate_completion(recovery, almost)
        .await
        .expect("backdate");
    let response = scenario.confirm(&cookie).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "a minute before");
    database
        .recoveries()
        .backdate_completion(recovery, Duration::minutes(2))
        .await
        .expect("settle");
    let response = scenario.confirm(&cookie).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "once settled");
}

/// A link enrolls one passkey even when two of its ceremonies started before
/// either finished: the second finish fails, stores no passkey, and leaves the
/// recovery bound to the first, which stays in probation.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_link_enrolls_once_however_many_ceremonies_started() {
    let scenario = Scenario::new().await;
    let token = scenario.recover().await;
    let body = json!({ "token": token });
    let mut started = Vec::new();
    for _ in 0..2 {
        let start = scenario
            .keys
            .start(routes::recovery::START, "", body.clone())
            .await;
        started.push(start);
    }
    let finish = async |(started, browser): &(Value, String)| {
        let body = json!({
            "ceremony_id": started["ceremony_id"],
            "credential": scenario.keys.credential(started),
            "friendly_name": "Recovered",
        });
        scenario
            .keys
            .request(routes::recovery::FINISH, Method::POST, browser, body)
            .await
    };
    let first = finish(&started[0]).await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    let bound = scenario.latest().await.passkey_id;
    let second = finish(&started[1]).await;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(code(second).await, "invalid_link");
    assert_eq!(scenario.passkeys().await.len(), 2, "no second passkey");
    assert_eq!(scenario.latest().await.passkey_id, bound, "still the first");
}
