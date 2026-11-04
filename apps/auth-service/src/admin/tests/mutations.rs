//! How a change waits on locks and rechecks its caller after waiting.

use super::*;

/// A mutation checks its caller's confirmation after its last write: one admitted
/// just inside the window, that then waited for a logout holding the target's
/// session, is refused with the step-up and changes nothing.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn mutations_recheck_the_confirmation_after_waiting() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let auth_time = Utc::now() - Duration::seconds(298);
    let mut logout = harness.database.begin().await.expect("transaction");
    user.sign_out(&mut logout).await;
    let service = harness.service();
    let reason = reason("Spam");
    let operator = operator(admin, auth_time);
    let (result, ()) = tokio::join!(
        service.disable_user(&operator, user.user_id, reason),
        async {
            until_blocked(&mut logout, 1).await;
            let expired = auth_time + Duration::seconds(301) - Utc::now();
            tokio::time::sleep(expired.to_std().unwrap_or_default()).await;
            logout.commit().await.expect("logout");
        }
    );
    assert!(
        matches!(result, Err(AdminError::StepUpRequired(_))),
        "{result:?}"
    );
    let stored = harness
        .database
        .users()
        .find_by_id(user.user_id)
        .await
        .expect("lookup")
        .expect("user");
    assert_eq!(stored.status, AccountStatus::Active);
}

/// A mutation waiting for its target holds no lock of its caller's, so a sign-in
/// that locks the target's account and then revokes the caller's session, as
/// switching accounts does, finishes first.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn waiting_mutations_hold_no_caller_locks() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let mut switch = harness.database.begin().await.expect("transaction");
    switch
        .users()
        .find_active_by_id_for_update(user.user_id)
        .await
        .expect("target lock");
    let service = harness.service();
    let reason = reason("Spam");
    let operator = operator(admin, Utc::now());
    let (result, ()) = tokio::join!(
        service.disable_user(&operator, user.user_id, reason),
        async {
            until_blocked(&mut switch, 1).await;
            // The switch revokes the caller's session without a deadlock.
            admin.sign_out(&mut switch).await;
            switch.commit().await.expect("commit");
        }
    );
    assert!(
        matches!(result, Err(AdminError::SessionEnded)),
        "{result:?}"
    );
}

/// A mutation never waits for its caller's session, which the caller's own
/// sign-in or social linking may hold while it waits for the mutation's locks.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn mutations_never_wait_for_the_callers_session() {
    let harness = Harness::new().await;
    let admin = harness.admin().await;
    let user = harness.account().await;
    let mut linking = harness.database.begin().await.expect("transaction");
    linking
        .sessions()
        .find_active_by_id_for_update(admin.session_id)
        .await
        .expect("caller session lock");
    let reason = reason("Spam");
    let disabled = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        harness
            .service()
            .disable_user(&operator(admin, Utc::now()), user.user_id, reason),
    )
    .await
    .expect("the mutation does not wait for the caller's session");
    assert!(disabled.is_ok(), "{disabled:?}");
    linking.rollback().await.expect("rollback");
}
