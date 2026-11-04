//! Signup from pending provider evidence, committed only with a first passkey.

use super::*;

/// Signup must create its first passkey and cannot claim an existing account’s email.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn onboarding_commits_only_with_first_key_and_browser_and_never_claims_existing_email() {
    let test = TestApp::new().await;
    let (pending, headers) = test.pending(None, None).await;
    assert!(
        FederationApplication::pending_signup(&test.app.database, &headers, TokenId::new())
            .await
            .is_err(),
        "registration must name the displayed pending signup"
    );
    FederationApplication::pending_signup(&test.app.database, &headers, pending.id)
        .await
        .expect("pending signup");
    let user = test.user(None, false).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        FederationApplication::attach_signup(
            &mut tx,
            &security::RequestContext::TEST.actor(piquel_common::events::Actor::Anonymous),
            pending.id,
            &headers,
            user
        )
        .await
        .is_err()
    );
    tx.rollback().await.expect("rollback");
    let mut tx = test.app.database.begin().await.expect("tx");
    test.key(&mut tx, user).await;
    assert!(
        FederationApplication::attach_signup(
            &mut tx,
            &security::RequestContext::TEST.actor(piquel_common::events::Actor::Anonymous),
            pending.id,
            &HeaderMap::new(),
            user
        )
        .await
        .is_err()
    );
    FederationApplication::attach_signup(
        &mut tx,
        &security::RequestContext::TEST.actor(piquel_common::events::Actor::Anonymous),
        pending.id,
        &headers,
        user,
    )
    .await
    .expect("first key authorizes signup");
    tx.commit().await.expect("commit");
    assert_eq!(
        test.app
            .database
            .federation()
            .find_active(&pending.issuer, &pending.subject)
            .await
            .expect("identity")
            .expect("linked")
            .user_id,
        user
    );
    let email = format!("{}@example.com", TokenId::new());
    test.user(Some(&email), true).await;
    let (pending, headers) = test.pending(None, Some(&email)).await;
    let mut tx = test.app.database.begin().await.expect("tx");
    assert!(
        FederationApplication::attach_signup(
            &mut tx,
            &security::RequestContext::TEST.actor(piquel_common::events::Actor::Anonymous),
            pending.id,
            &headers,
            user
        )
        .await
        .is_err()
    );
    tx.rollback().await.expect("rollback");
}
